# FEAT-125 非生产环境准备

## 目标与边界

本运行手册为 `FEAT-125-authoritative-permission-projection` 固定一个供应商中立、默认关闭的非生产环境契约。它用于准备和验证环境，不选择 IdP 厂商，不写入 production 配置，不激活权限投影，也不允许真实用户、真实租户或商家数据。

固定版本：

- contracts candidate：`9ec34abd6e7dfb5a23b0154d467694167224ebbb`；
- API S4：`360a526b679147472e7cc82ca7ac9db9d18a371d`；
- Desktop S5A：`3798c67d260237928730758c7ec4c1fbe6fcf7d2`；
- PostgreSQL migration：`2`；
- access-token audience：`https://api.yijie.ai`；
- Desktop callback：`http://127.0.0.1:{ephemeral-port}/oauth/callback`。

## 1. 验证安全模板

```bash
make feat-125-nonprod-template
```

模板 `environments/nonproduction/feat-125.template.yaml` 必须始终使用不可路由的保留域名、公开客户端占位符、合成数据策略和关闭状态的功能开关。模板不能直接用于运行应用。

## 2. 供应商侧准备

在选定的非生产 IdP 中创建 native/public client，并满足以下约束：

- Authorization Code Flow + PKCE `S256`；
- 不创建或下发 client secret；
- 仅允许精确 loopback callback 模板；运行时端口必须由操作系统动态分配；
- issuer、authorization、token、JWKS 和 revocation endpoint 必须为可信 HTTPS，且属于同一 origin；
- ID token 和 access token 使用 `RS256`；
- access token audience 固定为 `https://api.yijie.ai`，TTL 为 600 秒；
- refresh token 必须轮换；检测到 reuse 时撤销整个 token family；
- JWKS 至少公开一个带 `kid` 的 RSA 签名公钥；
- 仅创建合成用户、合成租户和合成角色。

将模板复制为 `environments/nonproduction/feat-125.local.yaml`，只替换以下公开信息：

- `identity.issuer`；
- `identity.authorization_endpoint`；
- `identity.token_endpoint`；
- `identity.jwks_uri`；
- `identity.revocation_endpoint`；
- `identity.public_client_id`；
- `api.origin`。

`feat-125.local.yaml` 已被 `.gitignore` 排除。任何 token、refresh token、authorization code、cookie、client secret 或用户凭证都不得进入该文件。

## 3. 部署前离线预检

```bash
make feat-125-nonprod-ready CONFIG=environments/nonproduction/feat-125.local.yaml
```

检查必须在部署前通过。失败时不得启动权限投影或 Desktop 原生登录开关。

## 4. API 非生产部署映射

保持权限投影关闭，先完成数据库迁移和健康检查：

```text
YIJIE_ENV=nonproduction
YIJIE_API_PERMISSION_PROJECTION_ENABLED=false
YIJIE_API_ACCESS_ISSUER=<identity.issuer>
YIJIE_API_ACCESS_JWKS_URL=<identity.jwks_uri>
```

数据库连接、Redis 地址和其他运行 secret 必须由环境 Secret Manager 注入，不得写入本仓库。部署 API 完整 SHA `360a526b679147472e7cc82ca7ac9db9d18a371d`，执行 migration `2`，仅导入可重复、可审计的合成身份/租户/RBAC 数据。

## 5. Desktop 非生产映射

在执行在线预检和 S5B UI 前，所有 Desktop 开关保持关闭：

```text
YIJIE_DESKTOP_NATIVE_AUTH_ENABLED=false
YIJIE_DESKTOP_PERMISSION_CONSUMER_ENABLED=false
YIJIE_DESKTOP_OIDC_ISSUER=<identity.issuer>
YIJIE_DESKTOP_OIDC_AUTHORIZATION_ENDPOINT=<identity.authorization_endpoint>
YIJIE_DESKTOP_OIDC_TOKEN_ENDPOINT=<identity.token_endpoint>
YIJIE_DESKTOP_OIDC_JWKS_URI=<identity.jwks_uri>
YIJIE_DESKTOP_OIDC_REVOCATION_ENDPOINT=<identity.revocation_endpoint>
YIJIE_DESKTOP_OIDC_CLIENT_ID=<identity.public_client_id>
YIJIE_DESKTOP_API_ORIGIN=<api.origin>
```

上述值是公开运行配置；token 生命周期仍由系统 Keychain 管理，禁止通过环境变量或仓库文件提供 token。

## 6. 在线预检

```bash
make feat-125-nonprod-online CONFIG=environments/nonproduction/feat-125.local.yaml
```

在线预检只做只读检查，单个 JSON 响应以流式读取限制为 256 KiB：

- OIDC discovery 的 issuer、authorization/token/JWKS/revocation endpoints 与已批准配置精确一致，并支持 code、PKCE `S256` 和 `RS256` ID token；
- JWKS 可访问且包含可用于 `RS256` 的 RSA 签名键；
- API `/healthz` 和 `/readyz` 返回成功 JSON；
- `/v1/me/tenants` 在开关关闭时返回 404。

预检不会请求 token、不会启动浏览器授权，也不会修改 IdP、数据库或 API 状态。

## 7. G3 完成判定

只有以下证据同时存在，才能把 G3 标记为通过：

- 离线 ready 检查通过；
- 非生产 DNS/TLS 与 IdP public client 已实际分配；
- API migration `2` 与合成 bootstrap 完成；
- 在线预检通过；
- 配置来源、执行人、时间和完整 SHA 已登记到 FEAT-125 需求包。

仅模板检查或本地 Compose 检查通过时，状态必须写成“prepared / external values pending”，不能写成 G3 passed。

## 回滚

1. 保持或恢复 API 与 Desktop 功能开关为 `false`；
2. 撤销非生产 refresh-token family 和测试会话；
3. 移除 Secret Manager 中本轮运行配置的旧版本；
4. 删除本地未跟踪的 `feat-125.local.yaml`（如已创建）；
5. 数据库只执行经过评审的向后兼容迁移，不使用 `docker compose down --volumes` 清理证据或数据。
