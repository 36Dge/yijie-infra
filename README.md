# yijie-infra

易界 AI 基础设施仓库。当前可运行范围为 local Docker Compose，并包含 FEAT-125 的供应商中立非生产准备层；尚未创建共享 staging 或生产环境。

## 当前包含

- PostgreSQL：`localhost:5432`，供 `yijie-api` 后续使用；
- Redis：`localhost:6379`；
- PostgreSQL + pgvector：`localhost:5433`，供 `yijie-knowledge` 后续使用。

Knowledge 数据库首次初始化时会执行 `CREATE EXTENSION vector`。当前只启用扩展，不创建向量表，也不预设 Embedding 维度。

## 本地开发

```bash
make dev-up
make dev-status
make dev-down
```

`make dev-up` 会等待三项服务全部通过健康检查后再返回。数据库端口只绑定到 `127.0.0.1`，不会暴露到局域网。命名 Volume 保存数据库和 Redis 数据，普通 `make dev-down` 不会删除数据；只有显式执行 `docker compose down --volumes` 才会删除这些本地数据。

## FEAT-125 非生产准备

提交到仓库的模板只包含不可路由的保留域名、公开客户端占位符和固定的候选版本：

```bash
make feat-125-nonprod-template
```

IdP 与 API 的真实非生产 HTTPS 地址分配后，把模板复制为不会被 Git 跟踪的 `environments/nonproduction/feat-125.local.yaml`，替换公开配置，再依次执行：

```bash
make feat-125-nonprod-ready CONFIG=environments/nonproduction/feat-125.local.yaml
make feat-125-nonprod-online CONFIG=environments/nonproduction/feat-125.local.yaml
```

离线检查固定 contracts、API、Desktop 完整 SHA，禁止生产环境、真实业务数据、client secret 和提前启用功能开关。在线预检验证 OIDC discovery、JWKS、API 健康状态，并确认 `/v1/me/tenants` 在激活前仍返回 404。完整操作和环境变量映射见 [docs/feat-125-nonproduction.md](docs/feat-125-nonproduction.md)。

## 说明

当前不包含 Terraform、Kubernetes、Helm 或云厂商配置。上云前需要确认云厂商、网络、安全和 Secret Manager 方案。FEAT-125 模板通过检查不表示真实 IdP、TLS、DNS 或共享 staging 已经就绪。
