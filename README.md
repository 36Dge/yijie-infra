# yijie-infra

易界 AI 基础设施仓库。当前初始化范围为 local Docker Compose only。

## 当前包含

- PostgreSQL：`localhost:5432`，供 `yijie-api` 后续使用；
- Redis：`localhost:6379`；
- PostgreSQL + pgvector：`localhost:5433`，供 `yijie-knowledge` 后续使用。

## 本地开发

```bash
make dev-up
make dev-down
```

## 说明

当前不包含 Terraform、Kubernetes、Helm 或云厂商配置。上云前需要确认云厂商、网络、安全和 Secret Manager 方案。
