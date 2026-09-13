# FEAT-153 受控工作流 local 栈

范围：local + demo_fast 的普通合成文本工作流；部署影响 semantic，wire 仍以兄弟 Contracts 的 workflow-local source 为准。本栈不进入 Chat 默认依赖，不启动 Desktop、模型、平台或付费调用。

## 顺序

在工作区中保持 `yijie-infra`、`yijie-api`、`yijie-coze`、`yijie-contracts` 为兄弟仓，正常打开本机原厂 Docker Desktop。当前验证平台 macOS arm64；固定镜像清单见 `config/workflow-local/images.lock.json`，须先通过原厂 Docker CLI 正常拉取该清单中的精确引用。本机已拉取的镜像才可构建/激活；up 不下载镜像。

```sh
make workflow-check
make workflow-init
make workflow-build
make workflow-up
make workflow-status
```

init 建立单独数据集，生成 ignored、owner-only 私密文件和匿名公共镜像客户端配置，不修改用户 Docker 登录配置。build 用固定 Go 镜像和 canonical Dockerfile 构建 API、真实 Coze 私有入口及 PG 测试镜像，记录前后同一源码摘要、实际 image ID；dirty 工作树摘要不是发布 commit。

up 顺序：四项依赖健康 → 显式 Coze migration → 显式 API migration → Coze 带凭据 ready → API 绑定 fixed scope 并 ready。新 MySQL volume 的55条上游 DDL由 Coze 脚本校验原始schema摘要后提取，不运行原建库/seed。现有volume不会重新执行init SQL，服务迁移仅expand且幂等。五项依赖/Coze仅internal网络，API另连专用workflow-edge桥以建立Docker的loopback端口发布；唯一宿主端口127.0.0.1:18888。数据库、Redis与MinIO均无host端口。

## 正常验证

API仓 `make workflow-qualify-build` 生成的 `bin/workflow-local/workflow-local-qualify` 支持正常真实HTTP全流程 `--evidence <新绝对路径>`，只需exact local/demo_fast/enabled/API profile和本数据集 `private/k-na.json` 路径。不要打印私文件值或把整个私目录复制进证据。完整证据只含source DTO和合成工作流事实；若complete=false，先查原operation，不自动重发。

```sh
make workflow-qualify-pg EVIDENCE=/absolute/path/to/complete-http-evidence.json
make workflow-stop
make workflow-up
# 用原HTTP证据与新K_NA执行qualifier --verify-evidence，只读核验重开持久化。
make workflow-stop
```

PG验证容器只连本内部网络，使用构建时固定的依赖缓存和真实PostgreSQL，不seed工作流、不清表。普通8并发Claim验证唯一意图，随后写入明确的storage qualification unknown回执和审计，不伪造引擎终态。

## 生命周期与保留

状态、精确container ID、epoch、镜像、私文件和本地日志位于 `environments/local/generated/feat-153/`，全部ignored。正常停止依次API→Coze→依赖，SIGTERM并无限grace；观察超过20秒返回STOP_PENDING，保留依赖和状态。不要用默认有限Docker stop、Ctrl-C转发、强杀或删除volume绕过。再次up仅移除已记录且正常停止的自有容器，不删除volume；重建服务容器时更换epoch/K_NA/K_AC，数据库密码与持久数据保留。

不支持自动清理、故障恢复、生产多租户、在途任务重启或向下migration。未知容器、镜像/源码变动、端口冲突均停止后续动作并保留事实；不领用其他项目。私日志需脱敏后才可复制进需求证据。默认历史故障/攻击测试按用户长期安全条款跳过，不能称全仓测试通过。


第4步真实运行纠正：Docker29在API仅连接internal网络时没有实际发布host端口（容器内ready不足以证明可用）。因此API同时连接独立project的workflow-edge桥，仅发布127.0.0.1:18888；其余Coze/数据库/Redis/MinIO与测试runner仅internal。API无通用外部代理或provider入口，所有当前业务请求固定私有Coze地址。不得把API边缘桥描述为物理禁止任何出站的网络。ready还需从宿主以K_NA确认真实API状态，且其他容器均healthy。

## 第5步编辑器产物登记

编辑器采用 API 仓 `config/workflow-editor-assets.schema.json` 的部署接口。Coze canonical
`scripts/yijie/workflow-editor.mjs` 单独构建真实编辑器，固定产物目录是兄弟仓
`yijie-coze/bin/workflow-editor/dist`；Infra 不运行其 install/build，也不生成浏览器 DTO。
产物完成、源码冻结且本栈正常 stopped 后，显式执行：

```sh
make workflow-check
make workflow-editor
make workflow-build
make workflow-up
make workflow-status
```

`workflow-editor` 只执行 canonical `node scripts/yijie/workflow-editor.mjs check` 和
Contracts 的 api/coze/desktop 三个 consumer `--check`，不启动服务、不迁移、不更换凭据。
它依据 API 的 schema 验证 manifest、固定相对路径、MIME、文件数、逐文件大小/hash 和总量，
并双采样源码/manifest。状态登记固定目录、manifest SHA、生产者 source.lock 原始字节 SHA、
三个 consumer lock SHA、base commit、manifest 的 source_digest、Infra 独立计算的 Coze
candidate、入口文件 hash 和预算；两种 source digest 独立保存，不能把算法当前相同当作
运行资格。历次登记保留在 `state.json` 的 `editor_registrations`，不覆盖旧资格证据。

未登记时仍只使用 `compose/workflow-local.yml`，原六服务没有编辑器依赖。登记后 controller
自动附加 `compose/workflow-editor.yml`，仅为 API 增加一个不自动创建宿主目录的 readonly
bind mount `/opt/yijie/workflow-editor`，以及三个 `YIJIE_WORKFLOW_EDITOR_*` 部署输入。
Compose env 仅含固定产物路径与公开摘要；bundle 不能包含机密、资源身份或 E。
`build/up` 前后重新执行 canonical check 并与完整登记对象比较，任一产物、源码或契约锁
漂移都会停止后续步骤并保留容器/数据。更新产物必须先正常 stop，完成 canonical 构建后
重新登记，再 build/up；不修改在线产物，不自动降级或取消登记。

ready 仍先要求六项健康检查及宿主 K_NA 的真实 `/v1/workflow-local/status`。编辑器登记后，
再以无凭据 GET `http://127.0.0.1:18888/editor/` 比对入口字节/hash、no-store、nosniff、
no-referrer 与固定 CSP；这证明静态宿主正在服务登记内容。iframe MessageChannel、E 到期、
dirty 保留重连以及 dev/packaged WebKit 行为必须另做普通真实资格，不能由静态检查或该
GET 直接宣称通过。所有旧攻击、权限故障、强杀测试继续跳过。
