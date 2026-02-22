# AWS Manager 🔐



## 功能
- 🔒 **登录保护** — 密码认证，支持在线修改密码
- 💾 **自动备份** — 新密钥创建后立即写入 `keys_backup.txt`

## 一键部署

```bash
bash <(curl -sL https://raw.githubusercontent.com/obace/aws-key-manager/main/setup.sh)
```

部署完成后访问 `http://服务器IP:5000`，默认密码 `admin888`。

## 手动部署

```bash
git clone https://github.com/obace/aws-key-manager.git
cd aws-key-manager
chmod +x setup.sh && ./setup.sh
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
