import re
import os
import time
import socks
import socket
import boto3
import threading
from flask import Flask, render_template, request, jsonify
from botocore.exceptions import ClientError
import urllib.request

app = Flask(__name__)

# 保存原始 socket
_original_socket = socket.socket
# 线程锁，防止并发修改全局 socket
_proxy_lock = threading.Lock()


def log_info(msg):
    print(f"[INFO] {msg}")


def log_error(msg):
    print(f"\033[91m[ERROR] {msg}\033[0m")


def _make_proxy_socket(proxy_url):
    """解析代理地址，返回配置好的 socks socket 类，不修改全局状态"""
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
    port = int(port)

    s = socks.socksocket()
    socks.set_default_proxy(socks.SOCKS5, host, port, True, username, password)
    return host, port, username, password


def setup_proxy(proxy_url):
    """设置全局 SOCKS5 代理"""
    with _proxy_lock:
        if not proxy_url or not proxy_url.strip():
            socket.socket = _original_socket
            return
        _make_proxy_socket(proxy_url)
        socket.socket = socks.socksocket
        log_info(f"代理已启用: {proxy_url}")


def _create_session_with_proxy(ak, sk, proxy_url):
    """创建 boto3 session，如有代理则先设置"""
    if proxy_url:
        setup_proxy(proxy_url)
    return boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk)


def parse_key_line(line):
    """从一行文本中解析 AK、SK 和备注"""
    ak_match = re.search(r"(AKIA[A-Z0-9]{16})", line)
    # SK 必须是 40 位且包含至少一个非十六进制字符（排除纯 hex hash）
    sk_match = re.search(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", line)

    if not ak_match or not sk_match:
        return None, None, ""

    ak = ak_match.group(1)
    sk = sk_match.group(1)

    # 提取备注：优先邮箱
    email_match = re.search(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
    if email_match:
        remark = email_match.group(1)
    else:
        remark = line.replace(ak, "").replace(sk, "").strip()
        remark = re.sub(r"[-=,;:\s|]+", " ", remark).strip()
        parts = remark.split()
        remark = parts[0] if parts else ""

    return ak, sk, remark


def rotate_single_key(ak, sk, proxy_url=None):
    """核心轮换逻辑，返回 (success, msg, new_ak, new_sk)"""
    try:
        session = _create_session_with_proxy(ak, sk, proxy_url)

        # 验证旧密钥
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            log_info(f"验证通过: {identity.get('Arn')}")
        except ClientError as e:
            return False, f"旧密钥无效: {e}", None, None

        iam = session.client("iam")

        # 清理多余密钥（AWS 限制每用户最多 2 个）
        try:
            existing = []
            for page in iam.get_paginator("list_access_keys").paginate():
                existing.extend(k["AccessKeyId"] for k in page["AccessKeyMetadata"])
            if len(existing) >= 2:
                for kid in existing:
                    if kid != ak:
                        log_info(f"删除闲置密钥: {kid}")
                        iam.delete_access_key(AccessKeyId=kid)
        except ClientError as e:
            return False, f"清理旧密钥失败: {e}", None, None

        # 创建新密钥
        try:
            created = iam.create_access_key()
            new_ak = created["AccessKey"]["AccessKeyId"]
            new_sk = created["AccessKey"]["SecretAccessKey"]
            log_info(f"新密钥创建成功: {new_ak}")
        except ClientError as e:
            return False, f"创建新密钥失败: {e}", None, None

        # 等待新密钥生效
        new_key_active = False
        for i in range(10):
            try:
                new_session = _create_session_with_proxy(new_ak, new_sk, proxy_url)
                new_session.client("sts").get_caller_identity()
                new_key_active = True
                log_info(f"新密钥验证成功 (第 {i+1} 次)")
                break
            except Exception:
                time.sleep(3)

        if not new_key_active:
            return True, "新密钥验证超时，未删除旧密钥，请手动检查", new_ak, new_sk

        # 删除旧密钥：优先用新密钥删，失败则用旧密钥自删
        deleted = False
        for client in [new_session.client("iam"), iam]:
            try:
                client.delete_access_key(AccessKeyId=ak)
                deleted = True
                break
            except Exception:
                continue

        msg = "成功 (旧密钥已删除)" if deleted else "新密钥已获取，但旧密钥删除失败"
        return True, msg, new_ak, new_sk

    except Exception as e:
        return False, f"系统错误: {str(e)}", None, None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    data = request.json
    proxy = data.get("proxy")
    line = data.get("line", "")

    if proxy:
        try:
            setup_proxy(proxy)
        except Exception as e:
            return jsonify({"success": False, "msg": f"代理错误: {e}", "raw": line})

    ak, sk, remark = parse_key_line(line)
    if not ak or not sk:
        return jsonify({"success": False, "msg": "无法识别密钥格式", "raw": line})

    success, msg, new_ak, new_sk = rotate_single_key(ak, sk, proxy)

    result = {
        "success": success, "msg": msg,
        "old_ak": ak, "new_ak": new_ak, "new_sk": new_sk, "remark": remark,
    }
    if success:
        parts = [remark, new_ak, new_sk] if remark else [new_ak, new_sk]
        result["output_line"] = " ".join(parts)

    return jsonify(result)


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.json
    proxy = data.get("proxy")
    line = data.get("line", "")

    if proxy:
        try:
            setup_proxy(proxy)
        except Exception as e:
            return jsonify({"success": False, "msg": f"代理错误: {e}", "raw": line})

    ak, sk, remark = parse_key_line(line)
    if not ak or not sk:
        return jsonify({"success": False, "msg": "格式错误", "raw": line})

    try:
        session = _create_session_with_proxy(ak, sk, proxy)
        identity = session.client("sts").get_caller_identity()
        return jsonify({
            "success": True,
            "msg": f"有效 (Account: {identity['Account']})",
            "remark": remark, "ak": ak, "sk": sk, "arn": identity["Arn"],
        })
    except Exception as e:
        return jsonify({
            "success": False, "msg": f"无效 ({e})",
            "remark": remark, "ak": ak, "sk": sk,
        })


@app.route("/api/check_proxy", methods=["POST"])
def api_check_proxy():
    data = request.json
    proxy = data.get("proxy")
    try:
        setup_proxy(proxy)
        with urllib.request.urlopen("http://checkip.amazonaws.com", timeout=10) as resp:
            ip = resp.read().decode().strip()
        return jsonify({"success": True, "ip": ip})
    except Exception as e:
        return jsonify({"success": False, "msg": str(e)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
