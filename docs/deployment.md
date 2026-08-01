# Deployment

当前运行时部署只支持 local Docker Compose。

```bash
make dev-up
```

FEAT-125 的默认关闭本地类生产 profile 使用独立命令，不能据此声称生产部署：

```bash
make feat-125-local-template
make feat-125-local-up
make feat-125-local-status
```

完整启动、显式 Node CA、API 映射、preflight 与完成标准见 [feat-125-local-lab.md](feat-125-local-lab.md)。macOS Keychain trust 不属于本轮 G3 执行范围。

FEAT-125 提供非生产配置验证与只读在线预检，但不包含云资源创建或生产激活：

```bash
make feat-125-nonprod-template
make feat-125-nonprod-ready CONFIG=environments/nonproduction/feat-125.local.yaml
make feat-125-nonprod-online CONFIG=environments/nonproduction/feat-125.local.yaml
```

未来真实外部环境的具体版本、环境变量和完成判定见 [feat-125-nonproduction.md](feat-125-nonproduction.md)。
