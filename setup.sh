#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

WORK_DIR="/opt/aws-key-rotator"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${GREEN}============================================${PLAIN}"
echo -e "${GREEN}   AWS Key Manager 一键部署脚本 v2.0${PLAIN}"
echo -e "${GREEN}============================================${PLAIN}"

# 1. 安装系统依赖
echo -e "${YELLOW}[1/4] 正在检查系统环境...${PLAIN}"
if [ -f /etc/debian_version ]; then
    apt-get update -y && apt-get install -y python3 python3-pip python3-venv screen
elif [ -f /etc/redhat-release ]; then
    yum install -y python3 python3-pip screen
else
    echo -e "${RED}不支持的操作系统，请手动安装 Python3${PLAIN}"
    exit 1
fi

# 2. 部署文件（直接从仓库复制，避免内嵌代码不同步）
echo -e "${YELLOW}[2/4] 正在部署文件...${PLAIN}"
mkdir -p "$WORK_DIR/templates"
cp "$SCRIPT_DIR/app.py" "$WORK_DIR/app.py"
cp "$SCRIPT_DIR/templates/index.html" "$WORK_DIR/templates/index.html"
[ -f "$SCRIPT_DIR/rotator.py" ] && cp "$SCRIPT_DIR/rotator.py" "$WORK_DIR/rotator.py"
[ -f "$SCRIPT_DIR/accounts.csv" ] && cp "$SCRIPT_DIR/accounts.csv" "$WORK_DIR/accounts.csv"

# 3. 安装 Python 依赖
echo -e "${YELLOW}[3/4] 正在安装 Python 依赖...${PLAIN}"
pip3 install flask boto3 pysocks --break-system-packages 2>/dev/null \
  || pip3 install flask boto3 pysocks

# 4. 配置服务并启动
echo -e "${YELLOW}[4/4] 正在配置服务...${PLAIN}"
if [ "$(id -u)" -eq 0 ]; then
    cat > /etc/systemd/system/aws-rotator.service <<EOF
[Unit]
Description=AWS Key Rotator Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORK_DIR
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable aws-rotator
    systemctl restart aws-rotator
else
    screen -dmS aws-rotator python3 "$WORK_DIR/app.py"
fi

IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo "localhost")
echo -e "${GREEN}============================================${PLAIN}"
echo -e "${GREEN}部署完成！服务已启动。${PLAIN}"
echo -e "${GREEN}访问地址: http://$IP:5000${PLAIN}"
echo -e "${GREEN}============================================${PLAIN}"
