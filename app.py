import re
import os
import time
import socks
import socket
import boto3
import threading
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from botocore.config import Config as BotoConfig
import urllib.request

app = Flask(__name__)
app.secret_key = os.urandom(24)

_base_dir = os.path.dirname(os.path.abspath(__file__))
_password_file = os.path.join(_base_dir, ".password")
_default_password = os.environ.get("AKM_PASSWORD", "admin888")
BACKUP_FILE = os.path.join(_base_dir, "keys_backup.txt")

def _get_password():
    if os.path.exists(_password_file):
        with open(_password_file, "r") as f:
            return f.read().strip()
    return _default_password

def _set_password(pwd):
    with open(_password_file, "w") as f:
        f.write(pwd)

_original_socket = socket.socket
_proxy_lock = threading.Lock()

def _backup_key(remark, new_ak, new_sk):
    try:
        with open(BACKUP_FILE, "a", encoding="utf-8") as f:
            parts = [remark, new_ak, new_sk] if remark else [new_ak, new_sk]
            f.write(" | ".join(parts) + "\n")
    except Exception as e:
        print(f"\033[91m[ERROR] 备份写入失败: {e}\033[0m")

_boto_config = BotoConfig(
    connect_timeout=10, read_timeout=20,
    retries={"max_attempts": 0}, max_pool_connections=1,
)
MAX_RETRIES = 3
RETRY_DELAY = 2


def _parse_proxy(proxy_url):
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
    with _proxy_lock:
        socket.socket = _original_socket
        if not proxy_url or not proxy_url.strip():
            return
        host, port, username, password = _parse_proxy(proxy_url)
        socks.set_default_proxy(socks.SOCKS5, host, port, True, username, password)
        socket.socket = socks.socksocket


def _detect_exit_ip():
    try:
        with urllib.request.urlopen("http://checkip.amazonaws.com", timeout=8) as resp:
            return resp.read().decode().strip()
    except Exception:
        return "未知"


def _call_with_retry(fn, proxy_url, retries=MAX_RETRIES):
    last_err = None
    for i in range(retries):
        try:
            return fn()
        except Exception as e:
            last_err = e
            if i < retries - 1:
                time.sleep(RETRY_DELAY)
                if proxy_url:
                    reconnect_proxy(proxy_url)
    raise last_err


def _setup_proxy(proxy_url, logs):
    """公共代理设置 + IP检测，返回日志"""
    if proxy_url:
        logs.append("🔌 断开旧连接...")
        logs.append(f"🔄 重连 SOCKS5: {proxy_url}")
        reconnect_proxy(proxy_url)
        logs.append(f"🌐 出口 IP: {_detect_exit_ip()}")
    else:
        logs.append("🌐 直连模式（无代理）")


def parse_key_line(line):
    ak_match = re.search(r"(AKIA[A-Z0-9]{16})", line)
    sk_match = re.search(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", line)
    if not ak_match or not sk_match:
        return None, None, ""
    ak, sk = ak_match.group(1), sk_match.group(1)
    email_match = re.search(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
    if email_match:
        return ak, sk, email_match.group(1)
    remark = re.sub(r"[-=,;:\s|]+", " ", line.replace(ak, "").replace(sk, "")).strip()
    parts = remark.split()
    return ak, sk, parts[0] if parts else ""


def rotate_single_key(ak, sk, proxy_url=None, remark=""):
    logs = []

    try:
        _setup_proxy(proxy_url, logs)

        logs.append(f"📡 开始处理...")
        sess = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)

        # 验证旧密钥
        logs.append(f"🔑 验证旧密钥 {ak[:8]}****...")
        try:
            identity = _call_with_retry(
                lambda: sess.client("sts", config=_boto_config).get_caller_identity(),
                proxy_url
            )
            logs.append(f"✅ 验证通过: {identity.get('Arn')}")
        except Exception as e:
            logs.append(f"❌ 旧密钥无效: {e}")
            return False, f"旧密钥无效: {e}", None, None, logs

        # 清理多余密钥
        logs.append("🔍 检查现有密钥数量...")
        try:
            def _list_and_clean():
                iam = sess.client("iam", config=_boto_config)
                existing = []
                for page in iam.get_paginator("list_access_keys").paginate():
                    existing.extend(k["AccessKeyId"] for k in page["AccessKeyMetadata"])
                logs.append(f"   当前密钥数: {len(existing)}")
                if len(existing) >= 2:
                    for kid in existing:
                        if kid != ak:
                            logs.append(f"🗑️ 删除闲置密钥: {kid}")
                            iam.delete_access_key(AccessKeyId=kid)
                return iam
            iam = _call_with_retry(_list_and_clean, proxy_url)
        except Exception as e:
            logs.append(f"❌ 清理失败: {e}")
            return False, f"清理旧密钥失败: {e}", None, None, logs

        # 创建新密钥
        logs.append("🆕 创建新密钥...")
        try:
            created = _call_with_retry(lambda: iam.create_access_key(), proxy_url)
            new_ak = created["AccessKey"]["AccessKeyId"]
            new_sk = created["AccessKey"]["SecretAccessKey"]
            logs.append(f"✅ 新密钥已创建: {new_ak}")
            _backup_key(remark, new_ak, new_sk)
            logs.append("💾 已备份到本地文件")
        except Exception as e:
            logs.append(f"❌ 创建失败: {e}")
            return False, f"创建新密钥失败: {e}", None, None, logs

        # 等待新密钥生效
        logs.append("⏳ 等待新密钥生效...")
        new_sess = boto3.Session(aws_access_key_id=new_ak, aws_secret_access_key=new_sk)
        new_key_active = False
        for i in range(10):
            try:
                new_sess.client("sts", config=_boto_config).get_caller_identity()
                new_key_active = True
                logs.append(f"✅ 新密钥已生效 (第 {i+1} 次尝试)")
                break
            except Exception:
                logs.append(f"   第 {i+1} 次验证未通过，等待 3s...")
                time.sleep(3)

        if not new_key_active:
            logs.append("⚠️ 新密钥验证超时，保留旧密钥")
            return True, "新密钥验证超时，未删除旧密钥", new_ak, new_sk, logs

        # 删除旧密钥
        logs.append(f"🗑️ 删除旧密钥 {ak}...")
        deleted = False
        for attempt in range(MAX_RETRIES):
            for make_client in [lambda: new_sess.client("iam", config=_boto_config), lambda: sess.client("iam", config=_boto_config)]:
                try:
                    make_client().delete_access_key(AccessKeyId=ak)
                    deleted = True
                    break
                except Exception:
                    continue
            if deleted:
                break
            logs.append(f"   删除失败，重连代理重试 ({attempt+1}/{MAX_RETRIES})...")
            if proxy_url:
                reconnect_proxy(proxy_url)
            time.sleep(RETRY_DELAY)

        if deleted:
            logs.append("✅ 旧密钥已删除，轮换完成")
        else:
            logs.append("⚠️ 旧密钥删除失败，请手动处理")

        msg = "成功 (旧密钥已删除)" if deleted else "新密钥已获取，但旧密钥删除失败"
        return True, msg, new_ak, new_sk, logs

    except Exception as e:
        logs.append(f"❌ 系统错误: {str(e)}")
        return False, f"系统错误: {str(e)}", None, None, logs


@app.route("/")
def login_page():
    if session.get("logged_in"):
        return redirect("/dashboard")
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    if request.json.get("password") == _get_password():
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


@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    err = _require_login()
    if err: return err
    data = request.json
    old_pwd = data.get("old_password", "")
    new_pwd = data.get("new_password", "")
    if old_pwd != _get_password():
        return jsonify({"success": False, "msg": "旧密码错误"})
    if len(new_pwd) < 4:
        return jsonify({"success": False, "msg": "新密码至少 4 位"})
    _set_password(new_pwd)
    return jsonify({"success": True, "msg": "密码已修改"})


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    err = _require_login()
    if err: return err
    data = request.json
    proxy, line = data.get("proxy"), data.get("line", "")
    ak, sk, remark = parse_key_line(line)
    if not ak or not sk:
        return jsonify({"success": False, "msg": "无法识别密钥格式", "raw": line})

    success, msg, new_ak, new_sk, logs = rotate_single_key(ak, sk, proxy, remark)
    result = {"success": success, "msg": msg, "logs": logs,
              "old_ak": ak, "new_ak": new_ak, "new_sk": new_sk, "remark": remark}
    if success:
        parts = [remark, new_ak, new_sk] if remark else [new_ak, new_sk]
        result["output_line"] = " | ".join(parts)
    return jsonify(result)


@app.route("/api/verify", methods=["POST"])
def api_verify():
    err = _require_login()
    if err: return err
    data = request.json
    proxy, line = data.get("proxy"), data.get("line", "")
    ak, sk, remark = parse_key_line(line)
    if not ak or not sk:
        return jsonify({"success": False, "msg": "格式错误", "raw": line, "logs": []})

    logs = []
    try:
        _setup_proxy(proxy, logs)
        logs.append(f"🔑 验证密钥 {ak[:8]}****...")
        sess = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)
        identity = _call_with_retry(
            lambda: sess.client("sts", config=_boto_config).get_caller_identity(), proxy
        )
        logs.append(f"✅ 有效 — Account: {identity['Account']}")
        logs.append(f"   ARN: {identity['Arn']}")
        return jsonify({"success": True, "logs": logs, "remark": remark, "ak": ak, "sk": sk,
                        "msg": f"有效 (Account: {identity['Account']})", "arn": identity["Arn"]})
    except Exception as e:
        logs.append(f"❌ 无效: {e}")
        return jsonify({"success": False, "msg": f"无效 ({e})", "logs": logs,
                        "remark": remark, "ak": ak, "sk": sk})


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


@app.route("/api/quota", methods=["POST"])
def api_quota():
    err = _require_login()
    if err: return err
    data = request.json
    proxy, line = data.get("proxy"), data.get("line", "")
    ak, sk, remark = parse_key_line(line)
    if not ak or not sk:
        return jsonify({"success": False, "msg": "格式错误", "raw": line, "logs": []})

    logs = []
    try:
        _setup_proxy(proxy, logs)
        logs.append(f"🔑 查询密钥 {ak[:8]}****...")
        sess = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)
        sq = sess.client("service-quotas", region_name="us-east-1", config=_boto_config)
        resp = _call_with_retry(
            lambda: sq.get_service_quota(ServiceCode="ec2", QuotaCode="L-1216C47A"), proxy
        )
        vcpus = int(resp["Quota"]["Value"])
        logs.append(f"✅ On-Demand vCPUs 配额: {vcpus}V")
        return jsonify({"success": True, "logs": logs, "remark": remark,
                        "ak": ak, "sk": sk, "vcpus": vcpus, "msg": f"{vcpus}V"})
    except Exception as e:
        logs.append(f"❌ 查询失败: {e}")
        return jsonify({"success": False, "msg": f"{e}", "logs": logs,
                        "remark": remark, "ak": ak})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
