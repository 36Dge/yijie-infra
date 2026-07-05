# AGENTS.md

## 仓库职责

`yijie-infra` 管理本地开发依赖、后续 IaC、CI/CD、观测和安全配置。

## 当前范围

local Docker Compose only。

## 禁止事项

- 不提交生产 secret；
- 不擅自加入云厂商配置；
- 不创建 Terraform、Kubernetes 或 Helm 生产配置，除非用户明确确认目标环境。

## 开发命令

```bash
make dev-up
make dev-down
make lint
```
