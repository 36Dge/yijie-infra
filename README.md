# yijie-infra

易界 AI 基础设施仓库。当前可运行范围为 local Docker Compose，并包含 FEAT-125 的供应商中立非生产准备层与默认不启动的本地类生产 OIDC/TLS lab；尚未创建共享 staging 或生产环境。

## 当前包含

- PostgreSQL：`localhost:5432`，供 `yijie-api` 后续使用；
- Redis：`localhost:6379`；
- PostgreSQL + pgvector：`localhost:5433`，供 `yijie-knowledge` 后续使用。

Knowledge 数据库首次初始化时会执行 `CREATE EXTENSION vector`。当前只启用扩展，不创建向量表，也不预设 Embedding 维度。

FEAT-125 另有显式 `feat-125-local` profile，包含 digest-pinned Keycloak、Keycloak 专用 PostgreSQL 和 Caddy。它只发布 `127.0.0.1:8443` 与 `127.0.0.1:9443`，普通本地开发命令不会自动启动。

## 本地开发

```bash
make dev-up
make dev-status
make dev-down
```

`make dev-up` 会等待三项服务全部通过健康检查后再返回。数据库端口只绑定到 `127.0.0.1`，不会暴露到局域网。命名 Volume 保存数据库和 Redis 数据，普通 `make dev-down` 不会删除数据；只有显式执行 `docker compose down --volumes` 才会删除这些本地数据。

## FEAT-125 非生产准备

当前无云资源阶段使用 G3-NP-LOCAL：

```bash
make feat-125-local-template
make feat-125-local-init-secrets
make dev-up
make feat-125-local-api-db
make feat-125-local-up
```

导出公开 CA 后，用 committed SHA 或经结构化评审的 worktree candidate 引用固定本轮 API/Desktop；随后通过 pinned HTTPS 核验 live realm/client/user inventory 并为两个合成用户置密，再启动 dedicated API 并执行 offline/online preflight。local lab 会启用 API projection，但保持 Desktop consumer 与 production/release 关闭；真实 JWT 生命周期仍为 S7/G5 NOT RUN。完整顺序、安全边界与回滚见 [docs/feat-125-local-lab.md](docs/feat-125-local-lab.md)。本地 PASS 不等于生产 G5/G6 PASS。

未来具备真实非生产资源时，仍可使用原供应商中立准备流程：

提交到仓库的模板只包含不可路由的保留域名、公开客户端占位符和固定的候选版本：

```bash
make feat-125-nonprod-template
```

IdP 与 API 的真实非生产 HTTPS 地址分配后，把模板复制为不会被 Git 跟踪的 `environments/nonproduction/feat-125.local.yaml`，替换公开配置，再依次执行：

```bash
make feat-125-nonprod-ready CONFIG=environments/nonproduction/feat-125.local.yaml
make feat-125-nonprod-online CONFIG=environments/nonproduction/feat-125.local.yaml
```

这一原 external nonproduction 流程仍是独立的 flag-off 模板：离线检查固定 contracts、API、Desktop 完整 SHA，禁止生产环境、真实业务数据、client secret 和提前启用功能开关；在线预检确认 `/v1/me/tenants` 仍返回 404。它不覆盖上面的 G3-NP-LOCAL 激活语义。完整操作和环境变量映射见 [docs/feat-125-nonproduction.md](docs/feat-125-nonproduction.md)。

## 说明

当前不包含 Terraform、Kubernetes、Helm 或云厂商配置。上云前需要确认云厂商、网络、安全和 Secret Manager 方案。FEAT-125 模板通过检查不表示真实 IdP、TLS、DNS 或共享 staging 已经就绪。
