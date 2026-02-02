# AWS Key Manager Pro 🚀

一个现代化、高颜值的 AWS 密钥管理工具，支持批量轮换密钥、智能验证密钥有效性，并配备 SOCKS5 代理支持。

![AWS Key Manager](https://img.shields.io/badge/AWS-Key_Manager-4F46E5?style=for-the-badge&logo=amazon-aws&logoColor=white) ![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white) ![Flask](https://img.shields.io/badge/Flask-Web-000000?style=for-the-badge&logo=flask&logoColor=white)

## ✨ 核心功能

*   **🔄 批量密钥轮换**：自动创建新密钥、验证可用性、安全删除旧密钥（支持智能清理闲置 Key）。
*   **✅ 批量密钥验证**：一键检测密钥是否存活，显示 Account ID 和 ARN。
*   **🌐 代理支持**：内置 SOCKS5 代理配置，支持代理连通性检测。
*   **🎨 现代化 UI**：极简设计，实时进度条，一键复制结果，导出 TXT。
*   **🛡️ 安全机制**：
    *   **双重删除保障**：新密钥验证不通过绝不删除旧密钥。
    *   **智能重试**：应对 AWS 全球节点传播延迟。
    *   **格式自动清洗**：智能识别邮箱/备注，过滤乱码。

## 🚀 快速部署

### 方法 1: 使用一键脚本 (推荐)

如果您已经将此仓库 Clone 到本地或服务器：

```bash
# 赋予执行权限
chmod +x setup.sh

# 运行安装脚本
./setup.sh
```

脚本会自动：
1.  检测系统环境 (Ubuntu/Debian/CentOS)。
2.  安装 Python3, Pip 及相关依赖。
3.  如果是 Root 用户，会自动创建 Systemd 服务并启动。
4.  如果是普通用户，会使用 `screen` 后台运行。

### 方法 2: 手动运行

```bash
# 1. 安装依赖
pip3 install -r requirements.txt

# 2. 启动服务
python3 app.py
```

访问地址：`http://localhost:5000`

## 📖 使用指南

### 1. 密钥轮换 (Rotate)
在左侧输入框粘贴您的密钥列表，格式支持极其宽容，例如：
*   `user@example.com AKIAxxxx SECRETxxxx`
*   `备注信息 AKIAxxxx SECRETxxxx`
*   `AKIAxxxx SECRETxxxx` (纯密钥)

点击 **“开始轮换”**，程序会自动：
1.  连接 AWS 验证旧密钥。
2.  如果账号满额 (2个Key)，自动删除非当前的闲置 Key。
3.  创建新 Key。
4.  循环验证新 Key 直到生效。
5.  删除旧 Key。
6.  输出格式化后的新密钥：`user@example.com NewAK NewSK`。

### 2. 密钥验证 (Verify)
切换到 **“密钥验证”** 标签页，粘贴密钥列表。
程序会快速检测有效性，并返回 Account ID。

### 3. SOCKS 代理
在右上角输入代理地址（如 `127.0.0.1:7890`），点击 **“检测”** 按钮确认连通性。

## ⚠️ 注意事项

*   **Private 仓库**：由于本仓库是私有的，无法直接使用公开的 `curl` 链接一键安装。请确保服务器有权访问此仓库，或者手动上传 `setup.sh`。
*   **安全性**：工具不保存任何密钥日志，所有操作在内存中完成。请妥善保管导出的密钥文件。

---
Made with ❤️ by Pi
