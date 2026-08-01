# Observability

当前未配置观测组件。后续可接入 OpenTelemetry Collector、Prometheus、Grafana 和 Loki。

FEAT-125 local lab 只启用 Keycloak 内部 health/metrics 以增强数据库 readiness；管理端口 `9000` 不发布，也不经 Caddy 暴露。该开关不等于已建立生产指标、告警、SLO 或日志管道。
