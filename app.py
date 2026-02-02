import re
import os
import socks
import socket
import boto3
from flask import Flask, render_template, request, jsonify
from botocore.exceptions import ClientError

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
    """
    设置 SOCKS 代理 (全局)
    注意：Flask 是多线程的，全局修改 socket 会影响所有请求。
    在这个简单的工具里，这是可接受的，因为代理通常是统一配置的。
    """
    if not proxy_url or not proxy_url.strip():
        # 恢复默认 socket
        if hasattr(socket, 'original_socket'):
            socket.socket = socket.original_socket
        return

    log_info(f"配置代理: {proxy_url}")
    try:
        # 保存原始 socket 以便恢复 (虽然这个脚本里可能一直用代理)
        if not hasattr(socket, 'original_socket'):
            socket.original_socket = socket.socket

        # 解析 proxy 字符串
        # 简单格式支持: host:port 或 user:pass@host:port (默认SOCKS5)
        # 也可以带 socks5:// 前缀
        
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
    """
    核心轮换逻辑
    返回: (success: bool, msg: str, new_ak: str, new_sk: str)
    """
    try:
        # 1. 连接 (Verify Old)
        session = boto3.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk
        )
        iam = session.client('iam')
        
        # 简单验证 (改用 STS get_caller_identity，兼容性更好)
        try:
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            log_info(f"验证通过: {identity.get('Arn')}")
        except ClientError as e:
            return False, f"旧密钥无效: {e}", None, None

        # 1.5. 检查并清理多余密钥 (激进策略)
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
                
                # 再次确认是否腾出位置 (可选，直接继续也行)
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
        # 增加重试机制，应对 AWS 传播延迟
        import time
        max_retries = 10
        retry_interval = 3
        new_key_active = False
        
        log_info("正在等待新密钥生效...")
        
        # 尝试用新密钥建立连接
        for i in range(max_retries):
            try:
                # 每次都要重新建立 session，确保没有缓存
                new_session = boto3.Session(
                    aws_access_key_id=new_ak,
                    aws_secret_access_key=new_sk
                )
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

        # 新密钥生效了，开始执行“处决”旧密钥
        deletion_success = False
        
        # 方案 A: 用新密钥处决 (最稳妥)
        try:
            log_info(f"尝试使用新密钥删除旧密钥 {ak} ...")
            new_iam = new_session.client('iam')
            new_iam.delete_access_key(AccessKeyId=ak)
            log_info(f"旧密钥 {ak} 已通过新密钥删除")
            deletion_success = True
        except Exception as e:
            log_error(f"方案 A 失败 ({e})，切换方案 B...")
            
            # 方案 B: 旧密钥“自杀” (最后手段)
            try:
                log_info(f"尝试使用旧密钥自我删除 {ak} ...")
                # 复用最开始的 iam client (它是用旧密钥建立的)
                iam.delete_access_key(AccessKeyId=ak)
                log_info(f"旧密钥 {ak} 已自我删除")
                deletion_success = True
            except Exception as e2:
                log_error(f"方案 B 也失败: {e2}")
        
        if deletion_success:
             return True, "成功 (旧密钥已删除)", new_ak, new_sk
        else:
             # 虽然拿到了新 Key，但旧 Key 没删掉，必须警告
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
    
    # 1. 设置代理
    if proxy:
        try:
            setup_proxy(proxy)
        except Exception as e:
            return jsonify({'success': False, 'msg': f"代理错误: {str(e)}", 'raw': line})

    # 2. 智能解析
    # 寻找 AK: AKIA 开头, 16位以上大写字母数字
    # 寻找 SK: 40位 base64 字符
    ak_pattern = r"(AKIA[A-Z0-9]{16})"
    sk_pattern = r"([A-Za-z0-9/+=]{40})"
    
    ak_match = re.search(ak_pattern, line)
    sk_match = re.search(sk_pattern, line)
    
    if not ak_match or not sk_match:
        return jsonify({'success': False, 'msg': "无法识别密钥格式", 'raw': line})
        
    old_ak = ak_match.group(1)
    old_sk = sk_match.group(1)
    
    # 2.5 智能提取备注 (优先抓取邮箱)
    # 邮箱正则
    email_pattern = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    email_match = re.search(email_pattern, line)
    
    if email_match:
        # 如果有邮箱，直接用邮箱作为唯一备注，丢弃其他杂质
        remark = email_match.group(1)
    else:
        # 没有邮箱，才退回到“剔除AK/SK”的方案
        remark = line.replace(old_ak, '').replace(old_sk, '').strip()
        # 清理多余的分隔符和乱码，只保留常规字符
        # 这里我们只保留字母、数字、中文、常见标点
        # 简单粗暴点：把分隔符 (----, |, 空格) 统一变成空格，然后取第一段或最后一段？
        # 为了稳妥，我们去掉连续的特殊符号
        remark = re.sub(r'[-=,;:\s|]+', ' ', remark).strip()
        # 如果太长或者包含乱七八糟的东西，尝试截断
        parts = remark.split()
        if parts:
            # 通常备注在最前面
            remark = parts[0]

    # 3. 执行轮换
    success, msg, new_ak, new_sk = rotate_single_key(old_ak, old_sk)
    
    result = {
        'success': success,
        'msg': msg,
        'old_ak': old_ak,
        'new_ak': new_ak,
        'new_sk': new_sk,
        'remark': remark
    }
    
    # 构建输出行
    if success:
        # 格式：备注 新AK 新SK
        # 如果备注是邮箱格式，这正符合要求
        out_parts = []
        if remark:
            out_parts.append(remark)
        out_parts.append(new_ak)
        out_parts.append(new_sk)
        result['output_line'] = " ".join(out_parts)
    
    return jsonify(result)

@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.json
    proxy = data.get('proxy')
    line = data.get('line', '')

    # 1. 设置代理
    if proxy:
        try:
            setup_proxy(proxy)
        except Exception as e:
            return jsonify({'success': False, 'msg': f"代理错误: {str(e)}", 'raw': line})

    # 2. 解析
    ak_pattern = r"(AKIA[A-Z0-9]{16})"
    sk_pattern = r"([A-Za-z0-9/+=]{40})"
    ak_match = re.search(ak_pattern, line)
    sk_match = re.search(sk_pattern, line)

    if not ak_match or not sk_match:
        return jsonify({'success': False, 'msg': "格式错误", 'raw': line})

    ak = ak_match.group(1)
    sk = sk_match.group(1)
    
    # 提取备注
    email_pattern = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    email_match = re.search(email_pattern, line)
    if email_match:
        remark = email_match.group(1)
    else:
        remark = line.replace(ak, '').replace(sk, '').strip()
        remark = re.sub(r'[-=,;:\s|]+', ' ', remark).strip()
        parts = remark.split()
        if parts: remark = parts[0]

    # 3. 验证
    try:
        session = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity.get('Account')
        arn = identity.get('Arn')
        
        return jsonify({
            'success': True,
            'msg': f"有效 (Account: {account_id})",
            'remark': remark,
            'ak': ak,
            'sk': sk,
            'arn': arn
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'msg': f"无效 ({str(e)})",
            'remark': remark,
            'ak': ak,
            'sk': sk
        })

@app.route('/api/check_proxy', methods=['POST'])
def api_check_proxy():
    data = request.json
    proxy = data.get('proxy')
    
    try:
        # 设置临时代理 (注意：这里setup_proxy是全局的，但在单用户场景下没问题)
        # 为了不影响全局，我们可以临时用 requests + proxies 参数，
        # 但既然我们在这个工具里是全局设定的，直接调用 setup_proxy 测试更真实。
        setup_proxy(proxy)
        
        # 使用 boto3 或者 requests 都可以，这里用 urllib 原生库减少依赖
        import urllib.request
        
        # 访问 checkip.amazonaws.com
        url = "http://checkip.amazonaws.com"
        req = urllib.request.Request(url)
        # 设置超时
        with urllib.request.urlopen(req, timeout=10) as response:
            ip = response.read().decode('utf-8').strip()
            
        return jsonify({'success': True, 'ip': ip})
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)})

if __name__ == '__main__':
    # 监听所有 IP，方便您访问
    app.run(host='0.0.0.0', port=5000, debug=True)
