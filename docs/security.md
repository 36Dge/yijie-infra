# Security

生产环境前必须定义：

- Secret Manager；
- 网络隔离；
- IAM；
- 日志脱敏；
- 审计策略；
- 数据保留策略。

FEAT-125 非生产准备额外要求：仅合成身份与租户、OIDC public client、可信 HTTPS、PKCE `S256`、`RS256`、短期 access token 和 refresh-token rotation。仓库中的模板只允许公开配置，不允许 client secret、token、cookie、authorization code 或真实用户数据。详见 [feat-125-nonproduction.md](feat-125-nonproduction.md)。

无云资源阶段的 G3-NP-LOCAL 同样禁止真实数据和 client secret。credential 必须为本机随机生成、ignored、owner-only；Caddy CA 私钥留在命名 volume，只导出 owner-only 的单一公开证书。本轮 Node 使用 `NODE_EXTRA_CA_CERTS`；Desktop 显式 CA 注入与系统浏览器 user Keychain trust 留到后续已批准阶段，G3 不修改 Keychain。任何 insecure TLS bypass 都是门禁失败。详见 [feat-125-local-lab.md](feat-125-local-lab.md)。
