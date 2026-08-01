# Environment

当前环境：

- local：本地开发；
- nonproduction preparation：FEAT-125 供应商中立配置模板、离线验证和在线只读预检；

`nonproduction preparation` 不是已部署的共享环境。真实 dev/staging 仍需要分配 IdP、DNS、可信 TLS、Secret Manager 和 API origin；prod 需要另行审批，且不得复用合成环境身份或配置。
