# FEAT-125 G3-NP-LOCAL 本地类生产运行手册

## 状态与完成边界

本手册把 `FEAT-125-authoritative-permission-projection` 的 G3 非生产准备落实为只使用本机资源的 `G3-NP-LOCAL`。它提供真实 OIDC、可信 HTTPS、独立 IdP 数据库、固定合成身份和只读在线预检，但不代表生产部署、生产配置、G5 或 G6 已完成。

只有离线门禁、API/IdP 实际启动、合成 bootstrap 和在线预检全部通过，才能登记 `G3-NP-LOCAL PASS`。只验证模板或 Compose 不能登记 PASS。PASS 可以绑定已结构化评审的 dirty worktree candidate，但必须记录 base commit 和确定性 candidate tree SHA-256，不能把 base commit 冒充本轮完整 SHA；提交完成后必须重渲染、重跑预检并用新完整 SHA 替换临时候选证据。

当前运行时状态为 `BLOCKED`：`yijie-api` 在 projection 开启时会在启动阶段立即通过默认 HTTPS client 拉取 JWKS，而本轮既未批准把 Caddy CA 写入 macOS Keychain，也未批准 API 专用 local CA client。Node 的显式 CA 只覆盖 provisioner/preflight 自身，不能让 API 启动。获得“精确 user Keychain trust”或“API local-profile-only CA pin”之一的单独授权前，不得执行 dedicated API startup/readiness 或在线 preflight，也不得登记 G3-NP-LOCAL PASS；静态门禁、local stack、live realm conformance、独立 synthetic bootstrap 与 offline ready 仍可执行并登记为部分证据。禁止用关闭 TLS 校验、推迟 JWKS 首次拉取或把 projection 改回 false 绕过该阻断。

## 固定拓扑

```text
系统浏览器 / Desktop / preflight
             │
             ├── https://localhost:8443 ── Caddy ── Keycloak:8080
             │                                      │
             │                                      └── 专用 PostgreSQL
             │
             └── https://localhost:9443 ── Caddy ── host.docker.internal:18080
                                                        yijie-api
                                                           │
                                                           └── 127.0.0.1:5432/
                                                               yijie_api_feat125_local
```

- 不修改 `/etc/hosts`；
- Caddy 只发布 `127.0.0.1:8443` 和 `127.0.0.1:9443`；
- Keycloak 与其 PostgreSQL 不发布端口；
- API 必须由宿主机独立监听 `127.0.0.1:18080`；
- API bootstrap/runtime DSN 必须固定为 loopback `127.0.0.1:5432` 上的专用逻辑数据库 `yijie_api_feat125_local`，不得复用 `yijie_api` 或其它数据库；
- callback 固定为 `http://127.0.0.1:{ephemeral-port}/oauth/callback`；
- Caddy 在转发 API 前直接对 `/v1/tasks`、`/v1/tasks/*` 返回 `404`；API 的 `feat-125-local-lab` profile 还必须不注册 Tasks handler。

三个新增服务均位于显式 `feat-125-local` Compose profile，普通 `make dev-up` 不会启动它们。

## 不可变镜像与本地资源

| 服务 | 不可变镜像 |
| --- | --- |
| Keycloak | `quay.io/keycloak/keycloak:26.7.0@sha256:0f198be292568439d700cdbfb893e69a6009bb43a94a06a945b1d3d506c76b13` |
| Keycloak PostgreSQL | `postgres:16.13-alpine@sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50` |
| Caddy | `caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` |

新增命名 volume：

- `yijie_feat125_keycloak_postgres_data`：Keycloak 专用数据库；
- `yijie_feat125_caddy_data`：Caddy 本地 CA、证书和 CA 私钥；
- `yijie_feat125_caddy_config`：Caddy 运行配置状态。

CA 私钥只存在于 Docker 命名 volume，任何脚本都不得导出它。仓库外导出的只有公开根证书，且权限为 `0600`。

API 授权状态使用既有 loopback `yijie-postgres` 容器中的专用逻辑数据库
`yijie_api_feat125_local`。该数据库必须从空 inventory 创建并只写入本手册的 tracked synthetic
matrix；不读取、迁移或复用 `yijie_api` 的既有本地数据。

## Realm 与 native client

realm 名称固定为 `yijie-local`，issuer 固定为：

```text
https://localhost:8443/realms/yijie-local
```

Desktop client `yijie-desktop-feat-125-local` 是无 secret 的 public/native client，只允许 Authorization Code Flow，强制 PKCE `S256`，禁用 implicit、password/direct grant 和 service account。Access token 使用 `RS256`，TTL 为 600 秒，audience 固定为 `https://api.yijie.ai`。

Keycloak 26.7.0 的官方 `RedirectUtilsTest.testVerifyRedirectUriNative` 证明：登记不带端口的 `http://127.0.0.1/oauth/callback` 后，运行时 `http://127.0.0.1:<随机端口>/oauth/callback` 会被接受，同时 path 仍做完整字符串匹配。因此 realm 不使用 `*`，也不放宽 callback path。Desktop access token 另通过 Keycloak 内置 user-session-note mapper 将 numeric `AUTH_TIME` 投影为 `nbf`；禁止用静态 `nbf=0`、script mapper、手工 bearer 或放宽 API required-claim verifier 代替。

realm 只包含两个没有 credential 的固定合成用户：

| username | OIDC subject |
| --- | --- |
| `feat125-synthetic-user-a` | `12500000-0000-4000-8000-000000000001` |
| `feat125-synthetic-user-b` | `12500000-0000-4000-8000-000000000002` |

用户密码只在本机生成并保存到 ignored、`0600` secrets 文件。后续 API bootstrap 应使用上述 subject 建立两用户 × 两租户交叉角色矩阵，不得使用真实用户或租户。

Keycloak 能提供 refresh-token rotation，但当前本地 provider 证据不宣称“reuse 自动撤销整个 family”。这一差异固定记录为 `provider_limit_documented`，`S7 auth-lifecycle` 状态必须保持 `NOT RUN`。它不阻断 S5B consumer implementation，但继续阻断 S7、G5 和任何生产激活；不得把本地 rotation 证据写成完整 A1/A2 PASS。

## 0. 前置条件

- macOS；
- Docker Desktop 与 Docker Compose v2；
- Node.js 24–26、pnpm 11；
- OpenSSL；
- 已评审的 API 与 Desktop committed SHA，或同一评审快照的 candidate tree digest；
- 既有 `yijie-postgres` 本地容器健康；本步骤会在专用空数据库上单独执行 migration `2`；
- 不使用真实数据、生产 IdP 或生产开关。

先执行静态门禁；该步骤不启动或停止容器：

```bash
pnpm install --frozen-lockfile
make lint
make test
make feat-125-local-template
```

## 1. 生成本机 credential

```bash
make feat-125-local-init-secrets
```

脚本使用 OpenSSL 生成四个互不相同的 256-bit 值，写入被 Git 忽略的：

```text
environments/local/feat-125.secrets.env
```

文件必须由当前用户持有，权限为 `0600` 或更严格，只能包含四个被批准的十六进制赋值。脚本拒绝覆盖既有文件，也不会打印密码。

## 2. 启动显式 local profile

```bash
make dev-up
make feat-125-local-api-db
make feat-125-local-up
make feat-125-local-status
```

`dev-up` 只确保既有 loopback PostgreSQL/Redis/pgvector 健康；`feat-125-local-api-db` 以幂等、非破坏方式创建或核验 owner=`yijie`、encoding=`UTF8` 的专用 API 数据库，不会删除或重建任何数据库。`local-up` 只启动 Keycloak PostgreSQL、Keycloak 和 Caddy，并等待三者 healthcheck；不会删除任何 volume。

Realm import 只在新 Keycloak 数据库第一次创建 realm 时生效；后续 realm schema 变化必须走受评审迁移，禁止通过静默删除 volume 强制重建。第 3 步会在置密前通过 pinned HTTPS 核验持久化后的 live realm，不得把静态 import 文件冒充运行态证据。

## 3. 导出公开 CA 并生成显式验证配置

先为 API 与 Desktop 生成不会混淆 base HEAD 与 dirty candidate 的实现引用：

```bash
make feat-125-local-worktree-reference REPO=../yijie-api
make feat-125-local-worktree-reference REPO=../yijie-desktop
```

clean worktree 输出 `commit:<full-sha>`；dirty worktree 输出 `candidate:<base-full-sha>:<candidate-tree-sha256>`。candidate digest 对 tracked diff 与全部非 ignored untracked 文件做两次完整采样，采样间任何变化都会 fail closed。只有结构化评审覆盖的同一状态才可作为 `API_REF`、`DESKTOP_REF`。

```bash
make feat-125-local-prepare \
  API_REF=<reviewed-api-reference> \
  DESKTOP_REF=<reviewed-desktop-reference>
```

该命令只从 Caddy volume 导出公开根证书，不导出私钥；随后计算文件 SHA-256，并渲染被 Git 忽略的：

```text
environments/local/feat-125.local-lab.yaml
```

CA 文件固定为：

```text
environments/local/generated/feat-125-caddy-root.crt
```

它必须是普通非 symlink 文件、最多 64 KiB、只包含一个有效 X.509 CA PEM、SHA-256 与配置一致，并使用 owner-only `0400` 或 `0600` 权限。

配置和 CA 验证通过后，核验 live realm 并为两个固定 synthetic user 设置本机生成的密码：

```bash
make feat-125-local-provision-users
```

该操作可重复执行，不打印 credential。它通过固定 `https://localhost:8443`、显式 CA 和 5 秒 deadline 获取短期 bootstrap admin session；置密前对受评审投影做深度精确比较：realm 的登录、brute-force、签名、token/session 与 refresh 设置；Desktop client 的 protocol、flow、PKCE、consent/frontchannel、redirect 与 scopes；API bearer-only client；唯一 audience mapper 的完整 config；以及恰好两个固定 synthetic user 的 ID/username/email、空 `requiredActions` 和 `data_classification=synthetic_only`。任何漂移都会 fail closed 且不更改用户密码。结束时撤销 admin refresh token，并用同一旧 refresh token 实际请求 token endpoint，只有稳定返回 `invalid_grant` 才算撤销成功。

Desktop 的后续 local-integration signed flow 使用显式 CA 注入；Node online preflight 通过 `NODE_EXTRA_CA_CERTS` 信任这一份固定 CA。该 Node 配置不会传递给宿主机 API，而 API 启动又会立即拉取 JWKS，因此在 CA 路径获得授权前仍受页首阻断；G3-NP-LOCAL 当前不修改 macOS Keychain。

仓库保留下面的人工 trust helper，供后续 S7/G5 在取得单独批准后使用；本轮不要执行，执行结果也不能计入 G3 PASS：

```bash
make feat-125-local-trust-ca
make feat-125-local-ca-status
```

`local-up`、`prepare`、offline ready 和 online preflight 都不会改变 Keychain。禁止使用 `NODE_TLS_REJECT_UNAUTHORIZED=0`、`danger_accept_invalid_certs`、`curl -k` 或任何 insecure TLS bypass。

## 4. 启动 dedicated API

本步骤当前受上述 CA 授权阻断。授权并完成相应可信 CA 路径后，API 必须使用 `feat-125-local-lab` service profile、独占端口和明确的 loopback bind，并以本地权限投影开启状态启动：

```text
YIJIE_ENV=nonproduction
YIJIE_API_SERVICE_PROFILE=feat-125-local-lab
YIJIE_API_PORT=18080
YIJIE_API_PERMISSION_PROJECTION_ENABLED=true
YIJIE_API_ACCESS_ISSUER=https://localhost:8443/realms/yijie-local
YIJIE_API_ACCESS_JWKS_URL=https://localhost:8443/realms/yijie-local/protocol/openid-connect/certs
```

数据库 DSN、Redis 和其它应用启动步骤以 `yijie-api` 仓库的已评审 runbook 为准。必须确认：

- 只监听 `127.0.0.1:18080`；
- `GET /healthz` 与 `GET /readyz` 成功；
- 无 bearer token 的 `/v1/me/tenants` 返回稳定 contract `401`：`WWW-Authenticate: Bearer`、`Cache-Control: no-store`、`code=unauthorized`；
- `feat-125-local-lab` profile 没有注册任何 legacy Tasks handler。

目标 `401` 只证明 projection handler 已注册且无凭证请求 fail closed，但到达这一状态前 API 启动阶段的 JWKS 首次拉取必须通过可信 TLS；这正是当前阻断。解决该信任路径后，签名 bearer token 访问、issuer/audience 组合验证和完整 token 生命周期仍属于 `S7 auth-lifecycle NOT RUN`，不计入 G3 PASS；不得通过新增未评审的 CA 环境变量或 insecure TLS 绕过。

## 5. Synthetic bootstrap

在 `yijie-api` 中使用候选工作树已绑定的四份 tracked manifest，issuer 必须精确等于 `https://localhost:8443/realms/yijie-local`。固定矩阵：

| 身份 | 租户 A | 租户 B |
| --- | --- | --- |
| synthetic user A | owner | member |
| synthetic user B | member | owner |

本地 API DSN 必须由 ignored 本机配置注入，并精确使用 `postgres://<credential>@127.0.0.1:5432/yijie_api_feat125_local?sslmode=disable`；profile 会在读取 manifest、检查 migration 或打开数据库之前拒绝其它 host、port、database、query 或 issuer，且不会回显 DSN。

```bash
cd ../yijie-api
YIJIE_API_POSTGRES_DSN="$FEAT125_LOCAL_API_DSN" make migrate-up

for manifest in \
  config/nonproduction/feat-125-local-lab/user-a-tenant-a.json \
  config/nonproduction/feat-125-local-lab/user-a-tenant-b.json \
  config/nonproduction/feat-125-local-lab/user-b-tenant-a.json \
  config/nonproduction/feat-125-local-lab/user-b-tenant-b.json; do
  YIJIE_ENV=nonproduction \
  YIJIE_API_ACCESS_ISSUER='https://localhost:8443/realms/yijie-local' \
  YIJIE_API_POSTGRES_DSN="$FEAT125_LOCAL_API_DSN" \
    make bootstrap-nonprod-authz \
      BOOTSTRAP_PROFILE=feat-125-local-lab \
      INPUT="$manifest"
done
```

四份 bootstrap 首次执行和幂等复跑都必须登记 request ID、审计记录、authorization revision 和 diff。只读 inventory 必须证明恰好 2 users、2 identities、2 tenants、4 active memberships、4 role bindings、18 role permissions、8 success audits 和 0 Tasks；两 tenant revision 最终均为 3，第二次四个 diff 均为空。Infra 不复制应用数据库 schema。

## 6. 离线 ready 与在线 preflight

```bash
make feat-125-local-ready \
  CONFIG=environments/local/feat-125.local-lab.yaml \
  API_REF=<reviewed-api-reference> \
  DESKTOP_REF=<reviewed-desktop-reference>

make feat-125-local-online \
  CONFIG=environments/local/feat-125.local-lab.yaml \
  API_REF=<reviewed-api-reference> \
  DESKTOP_REF=<reviewed-desktop-reference>
```

离线 ready 会 fail closed 检查：

- contracts SHA，以及 API/Desktop 的 committed SHA 或显式 reviewed-worktree candidate 引用；
- local activation 与 permission projection 为 `true`，Desktop consumer、production 和 release 为 `false`；
- issuer 和 API origin 的 hostname 必须精确为 `localhost`，且 DNS 结果全部是 loopback；
- CA 文件、owner-only 权限与 SHA-256；
- 固定镜像 digest、端口、issuer、audience、PKCE、RS256 和 callback；
- 禁止 client secret 与 insecure TLS。

在线 preflight 只读检查：

- OIDC discovery 与批准 endpoint 精确一致；
- Code Flow、PKCE `S256`、RS256 和带 `kid` 的 RSA JWKS；
- authorize endpoint 接受动态端口的精确 `/oauth/callback`，并拒绝同端口错误 path；错误证据只记录 status 与脱敏后的 origin/path；
- API health/readiness；
- 已激活 `/v1/me/tenants` 与带固定 synthetic tenant header 的 `/v1/me/capabilities` 在无凭证时都返回稳定 contract `401`；
- 配置中的 `api.service_profile=feat-125-local-lab` 与启动环境精确一致；`GET /v1/tasks`、`POST /v1/tasks` 与子路径在 Caddy edge 和 direct `127.0.0.1:18080` 两层都返回 `404`，共同证明该 profile 的 Tasks 非注册语义；
- authorize 正/负检查保留手动 redirect 证据，其余请求禁止 redirect；JSON body 上限 256 KiB，单请求 deadline 5 秒。

## 7. PASS 证据

登记 `G3-NP-LOCAL PASS` 前至少保存：

- Infra、contracts 完整 SHA；API/Desktop 若已提交则登记完整 SHA，否则登记 reviewed candidate 的 base SHA + candidate tree SHA-256，并在提交后重跑、替换；
- 三个镜像 digest；
- CA 公钥文件 SHA-256，不登记私钥；
- Compose health 状态；
- 专用 API 数据库 migration 前空 inventory、migration v2，以及四份 tracked synthetic bootstrap 的 manifest digest、首次/幂等 request/audit/revision/diff 和最终精确 inventory；
- live realm/client/mapper/user conformance + HTTPS provision 命令、时间与退出码，以及 revoked refresh `invalid_grant` 证明；
- offline-ready 与 online-preflight 命令、时间、退出码；
- Tasks API handler 未注册与 edge 404 的双层证据；
- Keycloak realm 的 refresh rotation 配置证据已保存；family reuse 为 provider limitation，`S7 auth-lifecycle NOT RUN`；
- G3 必须验证 discovery/JWKS 经可信 TLS 拉取以及 API startup/readiness；真实 signed bearer 的 issuer/audience authorization lifecycle、macOS Keychain trust 与系统浏览器 signed flow 均为 `S7/G5 NOT RUN`；
- 明确写出生产 G5/G6 仍是 `DEFERRED`。

## 回滚

先把本地 API 权限投影和 Desktop 功能开关恢复为 `false`，撤销本地 session，然后停止本 profile：

```bash
make feat-125-local-stop
```

该命令保留全部命名 volume。若需要移除系统浏览器信任，先运行下面命令获得证书 fingerprint，再按脚本提示把同一 fingerprint 作为显式确认值重试：

```bash
make feat-125-local-untrust-ca
FEAT125_CONFIRM_CA_FINGERPRINT=<exact-fingerprint-from-previous-output> \
  make feat-125-local-untrust-ca
```

只有精确匹配的 FEAT-125 根证书与其 user trust 设置会被删除。删除本地配置、credential、容器或任何 volume 不属于普通回滚；尤其禁止未经单独数据影响审批运行 `docker compose down --volumes`、`docker volume rm` 或 `docker system prune`。
