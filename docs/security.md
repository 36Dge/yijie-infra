# Security

生产环境前必须定义：

- Secret Manager；
- 网络隔离；
- IAM；
- 日志脱敏；
- 审计策略；
- 数据保留策略。

FEAT-125 非生产准备额外要求：仅合成身份与租户、OIDC public client、可信 HTTPS、PKCE `S256`、`RS256`、短期 access token 和 refresh-token rotation。仓库中的模板只允许公开配置，不允许 client secret、token、cookie、authorization code 或真实用户数据。详见 [feat-125-nonproduction.md](feat-125-nonproduction.md)。
