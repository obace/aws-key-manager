#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

echo -e "${GREEN}============================================${PLAIN}"
echo -e "${GREEN}      AWS Key Manager 一键部署脚本 v1.0      ${PLAIN}"
echo -e "${GREEN}============================================${PLAIN}"

# 1. 检查并安装 Python3 & Pip
echo -e "${YELLOW}[1/4] 正在检查系统环境...${PLAIN}"

if [ -f /etc/debian_version ]; then
    OS="debian"
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv screen
elif [ -f /etc/redhat-release ]; then
    OS="centos"
    yum install -y python3 python3-pip screen
else
    echo -e "${RED}不支持的操作系统，请手动安装 Python3${PLAIN}"
    exit 1
fi

# 2. 创建目录结构
echo -e "${YELLOW}[2/4] 正在部署文件...${PLAIN}"
WORK_DIR="/opt/aws-key-rotator"
mkdir -p "$WORK_DIR/templates"

# 写入 app.py
cat > "$WORK_DIR/app.py" << 'EOF'
import re
import os
import socks
import socket
import boto3
from flask import Flask, render_template, request, jsonify
from botocore.exceptions import ClientError
import urllib.request

app = Flask(__name__)

# 配置颜色输出 (Backend logs)
class Colors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def log_info(msg):
    print(f"[INFO] {msg}")

def log_error(msg):
    print(f"{Colors.FAIL}[ERROR] {msg}{Colors.ENDC}")

def setup_proxy(proxy_url):
    if not proxy_url or not proxy_url.strip():
        if hasattr(socket, 'original_socket'):
            socket.socket = socket.original_socket
        return

    log_info(f"配置代理: {proxy_url}")
    try:
        if not hasattr(socket, 'original_socket'):
            socket.original_socket = socket.socket
        
        target = proxy_url.strip()
        if "://" in target:
            _, target = target.split("://")
        
        username = None
        password = None
        
        if "@" in target:
            auth, endpoint = target.split("@")
            username, password = auth.split(":")
        else:
            endpoint = target
            
        host, port = endpoint.split(":")
        port = int(port)

        socks.set_default_proxy(socks.SOCKS5, host, port, True, username, password)
        socket.socket = socks.socksocket
        log_info("代理已启用")
    except Exception as e:
        log_error(f"代理配置失败: {e}")
        raise e

def rotate_single_key(ak, sk):
    try:
        session = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)
        
        # 1. 验证旧密钥 (STS)
        try:
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            log_info(f"验证通过: {identity.get('Arn')}")
        except ClientError as e:
            return False, f"旧密钥无效: {e}", None, None

        iam = session.client('iam')

        # 1.5. 激进清理
        try:
            paginator = iam.get_paginator('list_access_keys')
            existing_keys = []
            for page in paginator.paginate():
                for key_meta in page['AccessKeyMetadata']:
                    existing_keys.append(key_meta['AccessKeyId'])
            
            if len(existing_keys) >= 2:
                log_info(f"检测到已有 {len(existing_keys)} 个密钥，开始清理...")
                for key_id in existing_keys:
                    if key_id != ak:
                        log_info(f"正在删除闲置密钥: {key_id}")
                        iam.delete_access_key(AccessKeyId=key_id)
        except ClientError as e:
            return False, f"检查/清理旧密钥失败: {e}", None, None

        # 2. 创建新密钥
        try:
            created = iam.create_access_key()
            new_ak = created['AccessKey']['AccessKeyId']
            new_sk = created['AccessKey']['SecretAccessKey']
            log_info(f"新密钥创建成功: {new_ak}")
        except ClientError as e:
            return False, f"创建新密钥失败: {e}", None, None

        # 3. 验证新密钥 & 删除旧密钥
        import time
        max_retries = 10
        retry_interval = 3
        new_key_active = False
        
        log_info("正在等待新密钥生效...")
        for i in range(max_retries):
            try:
                new_session = boto3.Session(aws_access_key_id=new_ak, aws_secret_access_key=new_sk)
                new_sts = new_session.client('sts')
                new_sts.get_caller_identity()
                new_key_active = True
                log_info(f"新密钥验证成功 (尝试第 {i+1} 次)")
                break
            except Exception as e:
                log_info(f"新密钥暂未生效 (尝试 {i+1}/{max_retries}): {e}")
                time.sleep(retry_interval)
        
        if not new_key_active:
             return True, f"轮换成功 (但新密钥验证超时，未删除旧密钥，请手动检查)", new_ak, new_sk

        # 删除旧密钥
        deletion_success = False
        try:
            log_info(f"尝试使用新密钥删除旧密钥 {ak} ...")
            new_iam = new_session.client('iam')
            new_iam.delete_access_key(AccessKeyId=ak)
            deletion_success = True
        except Exception as e:
            log_error(f"方案 A 失败 ({e})，切换方案 B...")
            try:
                log_info(f"尝试使用旧密钥自我删除 {ak} ...")
                iam.delete_access_key(AccessKeyId=ak)
                deletion_success = True
            except Exception as e2:
                log_error(f"方案 B 也失败: {e2}")
        
        if deletion_success:
             return True, "成功 (旧密钥已删除)", new_ak, new_sk
        else:
             return True, f"注意：新密钥已获取，但旧密钥删除失败！请手动检查。", new_ak, new_sk

    except Exception as e:
        return False, f"系统错误: {str(e)}", None, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/rotate', methods=['POST'])
def api_rotate():
    data = request.json
    proxy = data.get('proxy')
    line = data.get('line', '')
    
    if proxy:
        try:
            setup_proxy(proxy)
        except Exception as e:
            return jsonify({'success': False, 'msg': f"代理错误: {str(e)}", 'raw': line})

    ak_pattern = r"(AKIA[A-Z0-9]{16})"
    sk_pattern = r"([A-Za-z0-9/+=]{40})"
    ak_match = re.search(ak_pattern, line)
    sk_match = re.search(sk_pattern, line)
    
    if not ak_match or not sk_match:
        return jsonify({'success': False, 'msg': "无法识别密钥格式", 'raw': line})
        
    old_ak = ak_match.group(1)
    old_sk = sk_match.group(1)
    
    email_pattern = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    email_match = re.search(email_pattern, line)
    if email_match:
        remark = email_match.group(1)
    else:
        remark = line.replace(old_ak, '').replace(old_sk, '').strip()
        remark = re.sub(r'[-=,;:\s|]+', ' ', remark).strip()
        parts = remark.split()
        if parts: remark = parts[0]

    success, msg, new_ak, new_sk = rotate_single_key(old_ak, old_sk)
    
    result = {
        'success': success, 'msg': msg, 'old_ak': old_ak, 'new_ak': new_ak, 'new_sk': new_sk, 'remark': remark
    }
    
    if success:
        out_parts = []
        if remark: out_parts.append(remark)
        out_parts.append(new_ak)
        out_parts.append(new_sk)
        result['output_line'] = " ".join(out_parts)
    
    return jsonify(result)

@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.json
    proxy = data.get('proxy')
    line = data.get('line', '')

    if proxy:
        try:
            setup_proxy(proxy)
        except Exception as e:
            return jsonify({'success': False, 'msg': f"代理错误: {str(e)}", 'raw': line})

    ak_pattern = r"(AKIA[A-Z0-9]{16})"
    sk_pattern = r"([A-Za-z0-9/+=]{40})"
    ak_match = re.search(ak_pattern, line)
    sk_match = re.search(sk_pattern, line)

    if not ak_match or not sk_match:
        return jsonify({'success': False, 'msg': "格式错误", 'raw': line})

    ak = ak_match.group(1)
    sk = sk_match.group(1)
    
    email_pattern = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    email_match = re.search(email_pattern, line)
    if email_match:
        remark = email_match.group(1)
    else:
        remark = line.replace(ak, '').replace(sk, '').strip()
        remark = re.sub(r'[-=,;:\s|]+', ' ', remark).strip()
        parts = remark.split()
        if parts: remark = parts[0]

    try:
        session = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity.get('Account')
        arn = identity.get('Arn')
        
        return jsonify({
            'success': True, 'msg': f"有效 (Account: {account_id})", 'remark': remark, 'ak': ak, 'sk': sk, 'arn': arn
        })
    except Exception as e:
        return jsonify({'success': False, 'msg': f"无效 ({str(e)})", 'remark': remark, 'ak': ak, 'sk': sk})

@app.route('/api/check_proxy', methods=['POST'])
def api_check_proxy():
    data = request.json
    proxy = data.get('proxy')
    
    try:
        setup_proxy(proxy)
        url = "http://checkip.amazonaws.com"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            ip = response.read().decode('utf-8').strip()
        return jsonify({'success': True, 'ip': ip})
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

# 写入 templates/index.html
cat > "$WORK_DIR/templates/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Key Manager Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #4F46E5; 
            --primary-hover: #4338CA;
            --bg-body: #F3F4F6;
            --bg-card: #FFFFFF;
            --text-main: #111827;
            --text-sub: #6B7280;
            --border: #E5E7EB;
            --success: #10B981;
            --error: #EF4444;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --radius: 12px;
        }

        body { font-family: 'Inter', system-ui, -apple-system, sans-serif; background-color: var(--bg-body); color: var(--text-main); margin: 0; padding: 0; height: 100vh; display: flex; flex-direction: column; }
        .navbar { background-color: var(--bg-card); border-bottom: 1px solid var(--border); padding: 0 2rem; height: 64px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); }
        .brand { font-size: 1.25rem; font-weight: 700; color: var(--primary); display: flex; align-items: center; gap: 8px; }
        .proxy-bar { display: flex; align-items: center; gap: 12px; background: #F9FAFB; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--border); }
        .proxy-input { border: none; background: transparent; outline: none; font-size: 0.9rem; width: 240px; color: var(--text-main); }
        .btn-sm { padding: 4px 10px; font-size: 0.8rem; border-radius: 6px; }
        .main-container { flex: 1; padding: 2rem; max-width: 1400px; width: 100%; margin: 0 auto; box-sizing: border-box; display: flex; flex-direction: column; gap: 20px; }
        .tab-nav { display: flex; gap: 8px; margin-bottom: 10px; }
        .tab-btn { padding: 10px 24px; border-radius: 8px; font-weight: 500; color: var(--text-sub); cursor: pointer; transition: all 0.2s; background: transparent; }
        .tab-btn:hover { background: rgba(79, 70, 229, 0.05); color: var(--primary); }
        .tab-btn.active { background: var(--bg-card); color: var(--primary); box-shadow: var(--shadow); font-weight: 600; }
        .workspace { display: none; grid-template-columns: 1fr 1fr; gap: 24px; height: calc(100vh - 180px); }
        .workspace.active { display: grid; }
        .card { background: var(--bg-card); border-radius: var(--radius); box-shadow: var(--shadow); display: flex; flex-direction: column; overflow: hidden; border: 1px solid var(--border); }
        .card-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #FAFAFA; }
        .card-title { font-weight: 600; color: var(--text-main); font-size: 1rem; }
        .card-body { flex: 1; padding: 0; display: flex; flex-direction: column; position: relative; }
        textarea { flex: 1; width: 100%; border: none; padding: 20px; resize: none; font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9rem; line-height: 1.6; outline: none; box-sizing: border-box; background: #fff; }
        textarea::placeholder { color: #D1D5DB; }
        .log-area { background: #111827; color: #E5E7EB; }
        .card-footer { padding: 16px 20px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #fff; }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 10px 20px; border-radius: 8px; font-weight: 500; cursor: pointer; transition: all 0.2s; border: none; gap: 6px; }
        .btn-primary { background-color: var(--primary); color: white; box-shadow: 0 4px 6px rgba(79, 70, 229, 0.2); }
        .btn-primary:hover { background-color: var(--primary-hover); transform: translateY(-1px); }
        .btn-secondary { background-color: white; border: 1px solid var(--border); color: var(--text-main); }
        .btn-secondary:hover { background-color: #F9FAFB; border-color: #D1D5DB; }
        .btn-ghost { background: transparent; color: var(--text-sub); padding: 8px; }
        .btn-ghost:hover { color: var(--error); background: #FEF2F2; }
        .badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; background: #E5E7EB; color: #4B5563; }
        .progress-container { position: absolute; top: 0; left: 0; right: 0; height: 3px; background: transparent; z-index: 10; }
        .progress-bar { height: 100%; background: var(--success); width: 0; transition: width 0.3s ease; box-shadow: 0 0 10px rgba(16, 185, 129, 0.5); }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .workspace { animation: fadeIn 0.3s ease-out; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            AWS Key Manager
        </div>
        <div class="proxy-bar">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9CA3AF" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
            <input type="text" id="globalProxy" class="proxy-input" placeholder="SOCKS5 代理 (如 127.0.0.1:7890)">
            <button class="btn btn-secondary btn-sm" onclick="checkProxy()">检测</button>
            <span id="proxyStatus" style="font-size: 0.8rem; font-weight: 500; min-width: 80px; text-align: center;"></span>
        </div>
    </nav>
    <div class="main-container">
        <div class="tab-nav">
            <div class="tab-btn active" onclick="switchTab('rotate')">🔄 密钥轮换</div>
            <div class="tab-btn" onclick="switchTab('verify')">✅ 密钥验证</div>
        </div>
        <div id="tab-rotate" class="workspace active">
            <div class="card">
                <div class="card-header"><span class="card-title">旧密钥列表</span><span class="badge" id="rotateLines">0 行</span></div>
                <div class="card-body"><textarea id="rotateInput" placeholder="在此粘贴密钥列表..."></textarea></div>
                <div class="card-footer"><button class="btn btn-ghost" onclick="clearInput('rotate')">清空</button><button class="btn btn-primary" onclick="startTask('rotate')">开始轮换</button></div>
            </div>
            <div class="card">
                <div class="progress-container"><div id="rotateProgress" class="progress-bar"></div></div>
                <div class="card-header"><span class="card-title">新密钥结果</span><span class="badge" style="background: #D1FAE5; color: #065F46;" id="rotateCount">成功: 0</span></div>
                <div class="card-body"><textarea id="rotateOutput" class="log-area" readonly></textarea></div>
                <div class="card-footer"><button class="btn btn-secondary" onclick="downloadOutput('rotateOutput', 'new_keys.txt')">导出 TXT</button><button class="btn btn-primary" style="background: var(--success);" onclick="copyOutput('rotateOutput')">一键复制</button></div>
            </div>
        </div>
        <div id="tab-verify" class="workspace">
            <div class="card">
                <div class="card-header"><span class="card-title">待验证列表</span><span class="badge" id="verifyLines">0 行</span></div>
                <div class="card-body"><textarea id="verifyInput" placeholder="在此粘贴需要验证的密钥列表..."></textarea></div>
                <div class="card-footer"><button class="btn btn-ghost" onclick="clearInput('verify')">清空</button><button class="btn btn-primary" onclick="startTask('verify')">开始验证</button></div>
            </div>
            <div class="card">
                <div class="progress-container"><div id="verifyProgress" class="progress-bar"></div></div>
                <div class="card-header"><span class="card-title">验证报告</span><span class="badge" style="background: #DBEAFE; color: #1E40AF;" id="verifyCount">有效: 0</span></div>
                <div class="card-body"><textarea id="verifyOutput" class="log-area" readonly></textarea></div>
                <div class="card-footer"><button class="btn btn-secondary" onclick="downloadOutput('verifyOutput', 'valid_keys.txt')">导出 TXT</button><button class="btn btn-primary" style="background: var(--success);" onclick="copyOutput('verifyOutput')">一键复制</button></div>
            </div>
        </div>
    </div>
    <script>
        function switchTab(tabName) {
            document.querySelectorAll('.workspace').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + tabName).classList.add('active');
            const btns = document.querySelectorAll('.tab-btn');
            if (tabName === 'rotate') btns[0].classList.add('active');
            else btns[1].classList.add('active');
        }
        const proxyInput = document.getElementById('globalProxy');
        ['rotate', 'verify'].forEach(type => {
            const input = document.getElementById(type + 'Input');
            const counter = document.getElementById(type + 'Lines');
            input.addEventListener('input', () => {
                const lines = input.value.trim().split('\n').filter(l => l.trim());
                counter.textContent = `${lines.length} 行`;
            });
        });
        function clearInput(type) { document.getElementById(type + 'Input').value = ""; document.getElementById(type + 'Lines').textContent = "0 行"; }
        async function checkProxy() {
            const proxy = proxyInput.value;
            const statusSpan = document.getElementById('proxyStatus');
            if (!proxy) { statusSpan.textContent = "直连模式"; statusSpan.style.color = "#9CA3AF"; return; }
            statusSpan.textContent = "检测中..."; statusSpan.style.color = "#6B7280";
            try {
                const response = await fetch('/api/check_proxy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proxy: proxy }) });
                const res = await response.json();
                if (res.success) { statusSpan.textContent = `✅ ${res.ip}`; statusSpan.style.color = "#10B981"; } else { statusSpan.textContent = `❌ 失败`; statusSpan.title = res.msg; statusSpan.style.color = "#EF4444"; }
            } catch (e) { statusSpan.textContent = `❌ 错误`; statusSpan.style.color = "#EF4444"; }
        }
        async function startTask(type) {
            const inputArea = document.getElementById(type + 'Input');
            const outputArea = document.getElementById(type + 'Output');
            const progressFill = document.getElementById(type + 'Progress');
            const countText = document.getElementById(type + 'Count');
            const lines = inputArea.value.trim().split('\n').filter(l => l.trim());
            if (lines.length === 0) { alert("请先输入内容！"); return; }
            outputArea.value = ""; let successCount = 0; let processed = 0; const total = lines.length;
            const apiUrl = type === 'rotate' ? '/api/rotate' : '/api/verify';
            progressFill.style.width = "0%";
            for (const line of lines) {
                processed++; progressFill.style.width = `${(processed / total) * 100}%`;
                try {
                    const response = await fetch(apiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proxy: proxyInput.value, line: line }) });
                    const res = await response.json();
                    if (res.success) { successCount++; if (type === 'rotate') { outputArea.value += res.output_line + "\n"; } else { outputArea.value += `[有效] ${res.remark} | ${res.ak} | ${res.msg}\n`; } } else { outputArea.value += `[失败] ${line.substring(0, 30)}... | ${res.msg}\n`; }
                } catch (e) { outputArea.value += `[错误] 系统异常: ${e.message}\n`; }
                outputArea.scrollTop = outputArea.scrollHeight; const label = type === 'rotate' ? '成功' : '有效'; countText.textContent = `${label}: ${successCount}/${total}`;
            }
        }
        function copyOutput(id) { document.getElementById(id).select(); document.execCommand('copy'); alert("已复制！"); }
        function downloadOutput(id, filename) { const val = document.getElementById(id).value; const blob = new Blob([val], { type: "text/plain" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url); }
    </script>
</body>
</html>
EOF

# 3. 安装依赖
echo -e "${YELLOW}[3/4] 正在安装 Python 依赖...${PLAIN}"
pip3 install flask boto3 pysocks > /dev/null 2>&1

# 4. 创建 Systemd 服务 (可选，方便自启)
# 如果是 Root 用户，配置 systemd
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${YELLOW}[3.5/4] 配置 Systemd 服务...${PLAIN}"
    cat > /etc/systemd/system/aws-rotator.service << EOF
[Unit]
Description=AWS Key Rotator Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORK_DIR
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable aws-rotator
    systemctl restart aws-rotator
    
    # 获取 IP
    IP=$(curl -s http://checkip.amazonaws.com || echo "localhost")
    echo -e "${GREEN}============================================${PLAIN}"
    echo -e "${GREEN}部署完成！服务已启动。${PLAIN}"
    echo -e "${GREEN}访问地址: http://$IP:5000${PLAIN}"
    echo -e "${GREEN}============================================${PLAIN}"
else
    # 非 Root 用户，直接启动
    echo -e "${YELLOW}[4/4] 正在启动服务 (Screen)...${PLAIN}"
    screen -dmS aws-rotator python3 "$WORK_DIR/app.py"
    
    echo -e "${GREEN}============================================${PLAIN}"
    echo -e "${GREEN}部署完成！服务后台运行中。${PLAIN}"
    echo -e "${GREEN}如果需要停止: screen -X -S aws-rotator quit${PLAIN}"
    echo -e "${GREEN}============================================${PLAIN}"
fi
