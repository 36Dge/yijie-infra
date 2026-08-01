# Security Policy

本地 compose 中的账号密码是开发假值，不得复用于生产。生产 secret 必须进入专用 Secret Manager。

FEAT-125 非生产配置只允许提交不可路由模板。真实非生产公开配置放在被忽略的 `environments/nonproduction/feat-125.local.yaml`；token、cookie、authorization code、client secret 和真实用户数据不得写入任何仓库文件。
