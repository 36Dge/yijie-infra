# yijie-infra

易界 AI 基础设施仓库。当前初始化范围为 local Docker Compose only。

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

## 说明

当前不包含 Terraform、Kubernetes、Helm 或云厂商配置。上云前需要确认云厂商、网络、安全和 Secret Manager 方案。
