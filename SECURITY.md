# Security Policy

本地 compose 中的账号密码是开发假值，不得复用于生产。生产 secret 必须进入专用 Secret Manager。

FEAT-125 非生产配置只允许提交不可路由模板。真实非生产公开配置放在被忽略的 `environments/nonproduction/feat-125.local.yaml`；token、cookie、authorization code、client secret 和真实用户数据不得写入任何仓库文件。

FEAT-125 local lab 的密码只允许存在于 ignored、owner-only 的 `environments/local/feat-125.secrets.env`。Caddy CA 私钥只允许存在于 Docker 命名 volume；导出的单一公开 CA 证书必须小于等于 64 KiB 并保持 `0400` 或 `0600`。禁止提交、打印或记录 credential，禁止关闭 TLS 校验。G3 只允许 Node 显式 CA；系统浏览器 Keychain trust 需要后续单独批准，并按精确 fingerprint 回滚。详见 [docs/feat-125-local-lab.md](docs/feat-125-local-lab.md)。
