# Environment

当前环境：

- local：本地开发；
- local lab：FEAT-125 默认关闭的 Keycloak/Caddy/专用数据库类生产集成环境，只允许 loopback 与合成数据；
- nonproduction preparation：FEAT-125 供应商中立配置模板、离线验证和在线只读预检；

`local lab` 与 `nonproduction preparation` 都不是共享 staging 或生产环境。local lab 可以完成 G3/G4 工程集成证据，但 G5/G6 继续延后；真实 dev/staging 仍需要独立 IdP、DNS、可信 TLS、Secret Manager 和 API origin，prod 需要另行审批，且不得复用合成身份或配置。
