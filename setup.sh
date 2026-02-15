#!/bin/bash
set -e

GREEN='\033[0;32m' YELLOW='\033[0;33m' RED='\033[0;31m' PLAIN='\033[0m'
WORK_DIR="/opt/aws-key-rotator"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${GREEN}══════════════════════════════════════${PLAIN}"
echo -e "${GREEN}  AWS Key Manager 一键部署 v3.0${PLAIN}"
echo -e "${GREEN}══════════════════════════════════════${PLAIN}"

# 1. 系统依赖
echo -e "${YELLOW}[1/4] 安装系统依赖...${PLAIN}"
if [ -f /etc/debian_version ]; then
    apt-get update -qq && apt-get install -y -qq python3 python3-pip >/dev/null
elif [ -f /etc/redhat-release ]; then
    yum install -y -q python3 python3-pip >/dev/null
else
    echo -e "${RED}不支持的系统${PLAIN}"; exit 1
fi

# 2. Python 依赖
echo -e "${YELLOW}[2/4] 安装 Python 依赖...${PLAIN}"
pip3 install flask boto3 pysocks --break-system-packages -q 2>/dev/null \
  || pip3 install flask boto3 pysocks -q

# 3. 部署文件
echo -e "${YELLOW}[3/4] 部署文件...${PLAIN}"
mkdir -p "$WORK_DIR/templates"
cp "$SCRIPT_DIR/app.py" "$WORK_DIR/app.py"
cp "$SCRIPT_DIR/templates/index.html" "$WORK_DIR/templates/index.html"
cp "$SCRIPT_DIR/templates/login.html" "$WORK_DIR/templates/login.html"

# 4. systemd 服务
echo -e "${YELLOW}[4/4] 配置服务...${PLAIN}"
cat > /etc/systemd/system/aws-rotator.service <<EOF
[Unit]
Description=AWS Key Manager
After=network.target

[Service]
Type=simple
WorkingDirectory=$WORK_DIR
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now aws-rotator

IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || hostname -I | awk '{print $1}')
echo -e "${GREEN}══════════════════════════════════════${PLAIN}"
echo -e "${GREEN}  ✅ 部署完成！${PLAIN}"
echo -e "${GREEN}  🌐 http://$IP:5000${PLAIN}"
echo -e "${GREEN}  🔑 默认密码: admin888${PLAIN}"
echo -e "${GREEN}══════════════════════════════════════${PLAIN}"
