# Deployment

当前运行时部署只支持 local Docker Compose。

```bash
make dev-up
```

FEAT-125 提供非生产配置验证与只读在线预检，但不包含云资源创建或生产激活：

```bash
make feat-125-nonprod-template
make feat-125-nonprod-ready CONFIG=environments/nonproduction/feat-125.local.yaml
make feat-125-nonprod-online CONFIG=environments/nonproduction/feat-125.local.yaml
```

具体版本、环境变量和完成判定见 [feat-125-nonproduction.md](feat-125-nonproduction.md)。
