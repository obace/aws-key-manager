# AWS Key Manager 🔐

批量 AWS 密钥轮换 / 验证 / 配额查询工具，SOCKS5 代理支持，毛玻璃拟态 UI。

## 功能

- 🔄 **密钥轮换** — 自动创建新密钥、验证生效、删除旧密钥，智能清理闲置 Key
- ✅ **密钥验证** — 批量检测密钥有效性，返回 Account ID / ARN
- 📊 **配额查询** — 查询 us-east-1 On-Demand vCPUs 配额
- 🌐 **SOCKS5 代理** — 每个密钥操作前自动重连换 IP，失败自动重试 3 次
- 🔒 **登录保护** — 密码认证，支持在线修改密码
- 💾 **自动备份** — 新密钥创建后立即写入 `keys_backup.txt`

## 一键部署

```bash
bash <(curl -sH "Authorization: token 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" https://raw.githubusercontent.com/obace/aws-key-manager/main/setup.sh)
```

部署完成后访问 `http://服务器IP:5000`，默认密码 `admin888`。

## 手动部署

```bash
git clone https://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@github.com/obace/aws-key-manager.git
cd aws-key-manager
chmod +x setup.sh && ./setup.sh
```

## 输入格式

支持多种格式，自动识别 AK/SK 和备注：

```
user@example.com AKIA... SECRET...
备注 AKIA... SECRET...
AKIA... SECRET...
```

## 输出格式

```
备注 | AK | SK              # 轮换 / 验证
备注 | AK | SK | 8V         # 配额查询
```

## 服务管理

```bash
systemctl status aws-rotator    # 查看状态
systemctl restart aws-rotator   # 重启
journalctl -u aws-rotator -f    # 实时日志
```

## 文件说明

```
app.py                  # Flask 后端
templates/index.html    # 主界面
templates/login.html    # 登录页
setup.sh                # 部署脚本
keys_backup.txt         # 密钥备份（自动生成，.gitignore）
.password               # 密码文件（自动生成，.gitignore）
```
