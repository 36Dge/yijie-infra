# Rollback

本地环境回滚：

```bash
make dev-down
```

`make dev-down` 保留命名 Volume。未经数据影响审批，不得使用 `--volumes`。

FEAT-125 非生产准备回滚以关闭 API/Desktop 功能开关、撤销测试会话和移除未跟踪配置为主；详细顺序见 [feat-125-nonproduction.md](feat-125-nonproduction.md#回滚)。

FEAT-125 local lab 使用 `make feat-125-local-stop` 单独停止，不影响常规本地服务且保留 Keycloak/Caddy volume。浏览器 CA trust 只允许按精确 fingerprint 显式删除。完整顺序见 [feat-125-local-lab.md](feat-125-local-lab.md#回滚)。
