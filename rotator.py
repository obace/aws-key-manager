import boto3
import csv
import os
import socks
import socket
import sys
import argparse
from botocore.exceptions import ClientError

# 配置颜色输出
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_success(msg):
    print(f"{Colors.OKGREEN}[SUCCESS] {msg}{Colors.ENDC}")

def print_error(msg):
    print(f"{Colors.FAIL}[ERROR] {msg}{Colors.ENDC}")

def print_info(msg):
    print(f"{Colors.OKCYAN}[INFO] {msg}{Colors.ENDC}")

def setup_proxy(proxy_url):
    """
    设置 SOCKS 代理
    格式: socks5://user:pass@host:port 或 socks5://host:port
    """
    if not proxy_url:
        return

    print_info(f"正在配置代理: {proxy_url}")
    
    try:
        # 解析简单的 proxy 字符串
        # 这里为了简单起见，假设格式为 host:port 或 user:pass@host:port (默认SOCKS5)
        # 实际生产中可以使用 urllib.parse
        
        # 移除协议前缀
        if "://" in proxy_url:
            scheme, proxy_url = proxy_url.split("://")
        else:
            scheme = "socks5"

        if "@" in proxy_url:
            auth, endpoint = proxy_url.split("@")
            username, password = auth.split(":")
        else:
            username = None
            password = None
            endpoint = proxy_url

        host, port = endpoint.split(":")
        port = int(port)

        socks.set_default_proxy(socks.SOCKS5, host, port, True, username, password)
        socket.socket = socks.socksocket
        print_success("代理配置成功！")
    except Exception as e:
        print_error(f"代理配置失败: {str(e)}")
        sys.exit(1)

def rotate_key(account_name, old_access_key, old_secret_key):
    print(f"\n{Colors.BOLD}--- 开始处理账号: {account_name} ---{Colors.ENDC}")
    
    # 1. 使用旧密钥连接
    try:
        session = boto3.Session(
            aws_access_key_id=old_access_key,
            aws_secret_access_key=old_secret_key
        )
        iam = session.client('iam')
        
        # 验证旧密钥是否有效 (简单的调用: get_user)
        user_info = iam.get_user()
        username = user_info['User']['UserName']
        print_info(f"旧密钥验证通过，用户名: {username}")
    except ClientError as e:
        print_error(f"旧密钥无效或连接失败: {e}")
        return None

    # 2. 创建新密钥
    try:
        print_info("正在创建新密钥...")
        create_response = iam.create_access_key()
        new_access_key = create_response['AccessKey']['AccessKeyId']
        new_secret_key = create_response['AccessKey']['SecretAccessKey']
        print_success(f"新密钥创建成功: {new_access_key}")
    except ClientError as e:
        print_error(f"创建新密钥失败: {e}")
        return None

    # 3. 验证新密钥 (等待 AWS 传播，通常需要几秒，但在脚本中我们可以尝试直接连接)
    # 为了保险，我们用新密钥建立一个新会话
    try:
        print_info("正在验证新密钥...")
        # 很多时候新密钥有即时性，但也可能需要稍微 sleep，这里直接试
        new_session = boto3.Session(
            aws_access_key_id=new_access_key,
            aws_secret_access_key=new_secret_key
        )
        new_iam = new_session.client('iam')
        # 尝试列出密钥作为验证
        new_iam.list_access_keys() 
        print_success("新密钥验证通过！")
    except Exception as e:
        print_error(f"新密钥验证失败 (可能需要等待传播，但为了安全不继续删除旧密钥): {e}")
        return None

    # 4. 删除旧密钥
    try:
        print_info(f"正在删除旧密钥: {old_access_key} ...")
        # 必须使用有效的客户端来删除，这里我们用刚刚验证过的新客户端（new_iam）来删除旧密钥
        # 这证明了新密钥确实有权限操作
        new_iam.delete_access_key(AccessKeyId=old_access_key)
        print_success("旧密钥已安全删除！")
    except ClientError as e:
        print_error(f"删除旧密钥失败: {e}")
        # 这里虽然删除失败，但新密钥已经生成并保存，需要人工介入删除旧的
        return {
            'AccountName': account_name,
            'NewAccessKeyId': new_access_key,
            'NewSecretAccessKey': new_secret_key,
            'Status': 'NewKeyCreated_OldKeyDeleteFailed'
        }

    return {
        'AccountName': account_name,
        'NewAccessKeyId': new_access_key,
        'NewSecretAccessKey': new_secret_key,
        'Status': 'Success'
    }

def main():
    parser = argparse.ArgumentParser(description='AWS 密钥批量轮换工具')
    parser.add_argument('--input', '-i', default='accounts.csv', help='输入文件路径 (CSV格式: AccountName,OldAccessKeyId,OldSecretAccessKey)')
    parser.add_argument('--output', '-o', default='new_keys.csv', help='输出文件路径')
    parser.add_argument('--proxy', '-p', help='SOCKS代理地址 (例如: 127.0.0.1:7890 或 user:pass@1.2.3.4:1080)')
    
    args = parser.parse_args()

    # 设置代理
    if args.proxy:
        setup_proxy(args.proxy)

    # 读取输入
    accounts = []
    if not os.path.exists(args.input):
        print_error(f"输入文件 {args.input} 不存在！")
        return

    with open(args.input, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            accounts.append(row)

    print_info(f"加载了 {len(accounts)} 个账号，准备开始轮换...")

    results = []

    for acc in accounts:
        result = rotate_key(acc['AccountName'], acc['OldAccessKeyId'], acc['OldSecretAccessKey'])
        if result:
            results.append(result)

    # 保存结果
    if results:
        keys = ['AccountName', 'NewAccessKeyId', 'NewSecretAccessKey', 'Status']
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        print(f"\n{Colors.OKGREEN}所有操作完成！结果已保存至: {args.output}{Colors.ENDC}")
    else:
        print(f"\n{Colors.WARNING}没有生成任何新密钥。{Colors.ENDC}")

if __name__ == "__main__":
    main()
