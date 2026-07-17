# AGENTS.md

## 适用范围

本文件适用于 `yijie-infra` 整个仓库。环境或部署目录中若出现更具体的 `AGENTS.md`，修改对应目录时以更具体的规则为准。

## 仓库职责与当前范围

`yijie-infra` 管理易界项目的本地开发依赖，并为未来 IaC、CI/CD、观测和安全配置保留边界。

当前唯一已确认和实现的范围是 local Docker Compose：

- `postgres:16-alpine`，绑定 `127.0.0.1:5432`，数据库 `yijie_api`；
- `redis:7-alpine`，绑定 `127.0.0.1:6379`；
- `pgvector/pgvector:pg16`，绑定 `127.0.0.1:5433`，数据库 `yijie_knowledge`；
- 三个命名 volume 用于保存本地数据；
- pgvector 首次创建新 volume 时通过 init SQL 启用 `vector` extension。

当前没有 Terraform、Kubernetes、Helm、云环境、Secret Manager、生产网络、正式观测或发布流水线。`scripts/deploy.sh` 只是提示占位，成功退出不代表发生了部署；`scripts/rollback.sh` 只停止本地 Compose，不是应用或数据回滚。

本地运行和 Docker 语义校验需要 Docker Compose v2。只有 `docker` CLI、没有 `docker compose` plugin 仍不满足前置条件；当前 `scripts/plan.sh` 只探测 `docker` 命令，遇到这种环境会在静态校验通过后失败。

## 仓库边界

- 不实现业务逻辑、数据库业务 schema、应用 migration 或平台连接器；
- 不提交生产 secret、access key、证书、kubeconfig、真实 DSN 或云账号信息；
- 不擅自选择云厂商、区域、网络、Kubernetes、Terraform、Secret Manager 或观测平台；
- 不把本地开发密码、端口和拓扑复制为 staging/production 配置；
- 不在未经确认时增加服务、开放端口、下载未审查镜像或引入持久化组件；
- 不用基础设施脚本绕过应用仓库的 migration 和数据治理规则。

## 当前目录约定

- `docker-compose.local.yml`：本地依赖拓扑的唯一 Compose 源；
- `.env.example`：本地假值和连接示例，不保存真实秘密；
- `init/pgvector/`：仅用于新 pgvector volume 的首次 extension 初始化；
- `scripts/compose-model.mjs`：Compose 静态模型和安全约束；
- `scripts/plan.sh`：静态校验，并在 Docker 可用时执行 `docker compose config`；
- `scripts/apply.sh`：本地 `docker compose up -d`，不等待健康检查；
- `scripts/rollback.sh`：本地 `docker compose down`，保留 volume；
- `scripts/deploy.sh`：云部署占位，不是有效部署入口；
- `environments/`、`deploy/`、`observability/`、`security/`、`ci/`：待方案确认的占位目录。

数据库表、索引和业务 migration 应分别放在 `yijie-api` 与 `yijie-knowledge`，不要继续追加到 Docker init 脚本。init SQL 在已有命名 volume 上不会重新执行。

## Compose 与本地数据规则

- 所有发布端口保持绑定到 loopback，不暴露到局域网；
- 镜像必须使用明确 tag，升级 PostgreSQL、Redis 或 pgvector 前评估数据格式、extension 和回滚兼容性；
- 每个持久服务需要 healthcheck、命名 volume 和明确的数据用途；
- `make dev-up` 使用 `--wait`，只有三项健康检查通过才表示本地依赖 ready；
- `make apply` 不等待健康检查，不能据其退出码声称服务 ready；
- 普通 `make dev-down` 和 `make rollback` 保留命名 volume；
- `docker compose down --volumes`、`docker volume rm`、`docker system prune` 等删除本地数据的命令必须先获得用户明确批准；
- 修改 init SQL 后，不能通过静默删除 volume 强制生效，应采用应用 migration 或说明需要用户选择的数据重建步骤；
- Docker volume 数据位于 Docker Desktop 管理空间，不位于 Git 仓库中。

## Secret 与网络安全

- 当前 `yijie/yijie` 是仅用于 loopback 本地开发的假凭据，不得复用于共享或生产环境；
- `.env`、override compose、日志和命令历史不得提交真实凭据；
- 未来环境使用专用 Secret Manager，不把秘密写进 Terraform state、镜像、Compose、GitHub Actions 明文或前端变量；
- 增加出站网络、host mount、Docker socket、privileged、host network 或广泛 capability 前必须做安全评审；
- 服务账户、IAM、网络分区、TLS、备份、审计和数据保留必须在生产部署前明确；
- 基础设施日志和观测数据必须执行 token、DSN、PII 和商家数据脱敏。

## 未来环境与变更原则

- local、dev、staging、production 的账号、网络、数据和 secret 完全隔离；
- 生产资源采用 plan、review、apply、verify、rollback 的可审计流程；
- IaC state backend、锁、加密、权限和恢复方案必须先于第一份生产资源定义；
- 数据库、队列和存储变更需要容量、备份、恢复、migration 和回滚方案；
- 观测、告警和 SLO 根据服务目标设计，不因目录存在就假定工具已经选定；
- 任何云端实现必须同步更新 ADR、环境、安全、部署和回滚文档。

## 必须先确认的决策

- 新本地服务、镜像版本、端口、volume、数据库、extension 和资源限制；
- 是否删除或重建本地数据 volume；
- 云厂商、账号、区域、网络、域名、证书、IAM 和 Secret Manager；
- Terraform/Kubernetes/Helm 版本、state、集群和部署模型；
- PostgreSQL/Redis 托管方案、备份、恢复、加密、保留和高可用；
- CI/CD、镜像 registry、制品签名、观测、告警和 SLO；
- 任何涉及真实凭据、付费资源、生产环境或不可逆操作的执行。

## 开发与验证

统一使用 pnpm 管理本仓库 Node 工具，不混用 npm 或 yarn。

```bash
pnpm install --frozen-lockfile
make lint       # 静态校验；检测到 docker 后还要求 Compose v2 config 可用
make test       # Node 测试和静态/语义 Compose 校验
make dev-up     # 启动并等待三项本地依赖健康
make dev-status # 查看容器和健康状态
make dev-down   # 停止容器但保留数据 volume
make plan       # 当前仅为本地 Compose plan
make apply      # 当前仅启动本地 Compose且不等待健康
make deploy     # 当前占位，不能视为部署
make rollback   # 当前只停止本地 Compose，不是数据回滚
```

- Compose、init SQL 或脚本改动至少执行 `make lint && make test`；
- 需要启动验证时执行 `make dev-up` 和 `make dev-status`，测试完成后按任务要求决定是否保留服务；
- 不为纯文档审核启动、停止或删除用户当前运行的容器；
- 无 Docker 时静态检查通过必须标记为“未执行 Docker 语义/运行验证”；只有 Docker CLI 但缺少 Compose v2 时命令会失败，应如实报告缺失前置条件。

## 完成标准

- 变更保持在已确认环境范围，没有擅自引入云或生产假设；
- 本地端口、healthcheck、volume、extension 和数据保留语义正确；
- secret、网络、权限和破坏性操作满足最小权限及显式确认要求；
- `make lint`、`make test` 及与改动相关的运行验证通过；
- 部署、回滚和 readiness 没有被占位脚本或单一退出码夸大；
- 未配置的云、备份、观测、生产安全和恢复能力被如实说明。
