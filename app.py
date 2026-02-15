import re
import os
import time
import socks
import socket
import boto3
import threading
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from botocore.exceptions import ClientError
from botocore.config import Config as BotoConfig
import urllib.request

app = Flask(__name__)
app.secret_key = os.urandom(24)
LOGIN_PASSWORD = os.environ.get("AKM_PASSWORD", "admin888")

_original_socket = socket.socket
_proxy_lock = threading.Lock()

# 密钥备份文件：每次生成新密钥立刻写入，防止响应丢失导致密钥丢失
BACKUP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys_backup.txt")


def _backup_key(remark, old_ak, new_ak, new_sk, msg):
    """新密钥创建后立刻写入本地文件，确保不丢失"""
    try:
        with open(BACKUP_FILE, "a", encoding="utf-8") as f:
            parts = [remark, new_ak, new_sk] if remark else [new_ak, new_sk]
            f.write(" | ".join(parts) + "\n")
    except Exception as e:
        log_error(f"备份写入失败: {e}")

# boto3 连接配置：短超时 + 不复用连接，确保每次请求都走新的 TCP 连接（触发代理换 IP）
_boto_config = BotoConfig(
    connect_timeout=10,
    read_timeout=15,
    retries={"max_attempts": 0},  # 我们自己控制重试
    max_pool_connections=1,
)

# 操作级别重试次数（应对不稳定代理）
MAX_RETRIES = 3
RETRY_DELAY = 2


def log_info(msg):
    print(f"[INFO] {msg}")


def log_error(msg):
    print(f"\033[91m[ERROR] {msg}\033[0m")


def _parse_proxy(proxy_url):
    """解析代理地址，返回 (host, port, username, password)"""
    target = proxy_url.strip()
    if "://" in target:
        _, target = target.split("://", 1)
    username = password = None
    if "@" in target:
        auth, endpoint = target.rsplit("@", 1)
        username, password = auth.split(":", 1)
    else:
        endpoint = target
    host, port = endpoint.rsplit(":", 1)
    return host, int(port), username, password


def reconnect_proxy(proxy_url):
    """强制重连代理（断开旧连接，建立新连接触发换 IP）"""
    with _proxy_lock:
        # 先恢复原始 socket，断开所有 socks 连接
        socket.socket = _original_socket
        if not proxy_url or not proxy_url.strip():
            return
        # 重新设置代理，下次建连时会走新的 TCP 连接 = 新出口 IP
        host, port, username, password = _parse_proxy(proxy_url)
        socks.set_default_proxy(socks.SOCKS5, host, port, True, username, password)
        socket.socket = socks.socksocket
        log_info(f"代理已重连: {proxy_url}")


def _detect_exit_ip():
    """探测当前出口 IP"""
    try:
        with urllib.request.urlopen("http://checkip.amazonaws.com", timeout=8) as resp:
            return resp.read().decode().strip()
    except Exception:
        return "未知"


def _new_session(ak, sk):
    """创建一个不复用连接的 boto3 session"""
    return boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)


def _call_with_retry(fn, proxy_url, retries=MAX_RETRIES):
    """带重试的调用包装，每次失败后重连代理"""
    last_err = None
    for i in range(retries):
        try:
            return fn()
        except Exception as e:
            last_err = e
            log_error(f"操作失败 (第 {i+1}/{retries} 次): {e}")
            if i < retries - 1:
                time.sleep(RETRY_DELAY)
                if proxy_url:
                    reconnect_proxy(proxy_url)
    raise last_err


def parse_key_line(line):
    """从一行文本中解析 AK、SK 和备注"""
    ak_match = re.search(r"(AKIA[A-Z0-9]{16})", line)
    sk_match = re.search(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", line)
    if not ak_match or not sk_match:
        return None, None, ""
    ak, sk = ak_match.group(1), sk_match.group(1)

    email_match = re.search(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
    if email_match:
        remark = email_match.group(1)
    else:
        remark = re.sub(r"[-=,;:\s|]+", " ", line.replace(ak, "").replace(sk, "")).strip()
        parts = remark.split()
        remark = parts[0] if parts else ""
    return ak, sk, remark


def rotate_single_key(ak, sk, proxy_url=None, remark=""):
    """核心轮换逻辑，返回 (success, msg, new_ak, new_sk, logs)"""
    logs = []

    def _log(s):
        logs.append(s)
        log_info(s)

    try:
        if proxy_url:
            _log("🔌 断开旧连接...")
            _log(f"🔄 重连 SOCKS5: {proxy_url}")
            reconnect_proxy(proxy_url)
            ip = _detect_exit_ip()
            _log(f"🌐 出口 IP: {ip}")
        else:
            _log("🌐 直连模式（无代理）")

        _log(f"📡 开始处理...")
        session = _new_session(ak, sk)

        # 验证旧密钥
        _log(f"🔑 验证旧密钥 {ak[:8]}****...")
        try:
            identity = _call_with_retry(
                lambda: session.client("sts", config=_boto_config).get_caller_identity(),
                proxy_url
            )
            _log(f"✅ 验证通过: {identity.get('Arn')}")
        except Exception as e:
            _log(f"❌ 旧密钥无效: {e}")
            return False, f"旧密钥无效: {e}", None, None, logs

        iam = session.client("iam", config=_boto_config)

        # 清理多余密钥
        _log("🔍 检查现有密钥数量...")
        try:
            existing = []
            for page in iam.get_paginator("list_access_keys").paginate():
                existing.extend(k["AccessKeyId"] for k in page["AccessKeyMetadata"])
            _log(f"   当前密钥数: {len(existing)}")
            if len(existing) >= 2:
                for kid in existing:
                    if kid != ak:
                        _log(f"🗑️ 删除闲置密钥: {kid}")
                        iam.delete_access_key(AccessKeyId=kid)
        except ClientError as e:
            _log(f"❌ 清理失败: {e}")
            return False, f"清理旧密钥失败: {e}", None, None, logs

        # 创建新密钥
        _log("🆕 创建新密钥...")
        try:
            created = _call_with_retry(lambda: iam.create_access_key(), proxy_url)
            new_ak = created["AccessKey"]["AccessKeyId"]
            new_sk = created["AccessKey"]["SecretAccessKey"]
            _log(f"✅ 新密钥已创建: {new_ak}")
            _backup_key(remark, ak, new_ak, new_sk, "created")
            _log("💾 已备份到本地文件")
        except Exception as e:
            _log(f"❌ 创建失败: {e}")
            return False, f"创建新密钥失败: {e}", None, None, logs

        # 等待新密钥生效
        _log("⏳ 等待新密钥生效...")
        new_key_active = False
        new_session = None
        for i in range(10):
            try:
                new_session = _new_session(new_ak, new_sk)
                new_session.client("sts", config=_boto_config).get_caller_identity()
                new_key_active = True
                _log(f"✅ 新密钥已生效 (第 {i+1} 次尝试)")
                break
            except Exception:
                _log(f"   第 {i+1} 次验证未通过，等待 3s...")
                time.sleep(3)

        if not new_key_active:
            _log("⚠️ 新密钥验证超时，保留旧密钥")
            return True, "新密钥验证超时，未删除旧密钥", new_ak, new_sk, logs

        # 删除旧密钥
        _log(f"🗑️ 删除旧密钥 {ak}...")
        deleted = False
        for client in [new_session.client("iam", config=_boto_config), iam]:
            try:
                client.delete_access_key(AccessKeyId=ak)
                deleted = True
                break
            except Exception:
                continue

        if deleted:
            _log("✅ 旧密钥已删除，轮换完成")
        else:
            _log("⚠️ 旧密钥删除失败，请手动处理")

        msg = "成功 (旧密钥已删除)" if deleted else "新密钥已获取，但旧密钥删除失败"
        return True, msg, new_ak, new_sk, logs

    except Exception as e:
        _log(f"❌ 系统错误: {str(e)}")
        return False, f"系统错误: {str(e)}", None, None, logs


@app.route("/")
def login_page():
    if session.get("logged_in"):
        return redirect("/dashboard")
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    if request.json.get("password") == LOGIN_PASSWORD:
        session["logged_in"] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "msg": "密码错误"})


@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/")
    return render_template("index.html")


def _require_login():
    if not session.get("logged_in"):
        return jsonify({"success": False, "msg": "未登录"}), 401
    return None


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    err = _require_login()
    if err: return err
    data = request.json
    proxy = data.get("proxy")
    line = data.get("line", "")

    ak, sk, remark = parse_key_line(line)
    if not ak or not sk:
        return jsonify({"success": False, "msg": "无法识别密钥格式", "raw": line})

    success, msg, new_ak, new_sk, logs = rotate_single_key(ak, sk, proxy, remark)

    result = {
        "success": success, "msg": msg, "logs": logs,
        "old_ak": ak, "new_ak": new_ak, "new_sk": new_sk, "remark": remark,
    }
    if success:
        parts = [remark, new_ak, new_sk] if remark else [new_ak, new_sk]
        result["output_line"] = " | ".join(parts)
    return jsonify(result)


@app.route("/api/verify", methods=["POST"])
def api_verify():
    err = _require_login()
    if err: return err
    data = request.json
    proxy = data.get("proxy")
    line = data.get("line", "")

    ak, sk, remark = parse_key_line(line)
    if not ak or not sk:
        return jsonify({"success": False, "msg": "格式错误", "raw": line, "logs": []})

    vlogs = []
    try:
        if proxy:
            vlogs.append("🔌 断开旧连接...")
            vlogs.append(f"🔄 重连 SOCKS5: {proxy}")
            reconnect_proxy(proxy)
            ip = _detect_exit_ip()
            vlogs.append(f"🌐 出口 IP: {ip}")
        else:
            vlogs.append("🌐 直连模式（无代理）")

        vlogs.append(f"🔑 验证密钥 {ak[:8]}****...")
        session = _new_session(ak, sk)
        identity = _call_with_retry(
            lambda: session.client("sts", config=_boto_config).get_caller_identity(),
            proxy
        )
        vlogs.append(f"✅ 有效 — Account: {identity['Account']}")
        vlogs.append(f"   ARN: {identity['Arn']}")
        return jsonify({
            "success": True, "logs": vlogs,
            "msg": f"有效 (Account: {identity['Account']})",
            "remark": remark, "ak": ak, "sk": sk, "arn": identity["Arn"],
        })
    except Exception as e:
        vlogs.append(f"❌ 无效: {e}")
        return jsonify({
            "success": False, "msg": f"无效 ({e})", "logs": vlogs,
            "remark": remark, "ak": ak, "sk": sk,
        })


@app.route("/api/check_proxy", methods=["POST"])
def api_check_proxy():
    err = _require_login()
    if err: return err
    data = request.json
    proxy = data.get("proxy")
    try:
        reconnect_proxy(proxy)
        with urllib.request.urlopen("http://checkip.amazonaws.com", timeout=10) as resp:
            ip = resp.read().decode().strip()
        return jsonify({"success": True, "ip": ip})
    except Exception as e:
        return jsonify({"success": False, "msg": str(e)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
