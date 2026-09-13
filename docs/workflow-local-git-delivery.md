# FEAT-153 local 工作流 Git 来源

2026-09-13。下列完整提交固定本期 local 候选；不代表生产 tag、镜像发布或 CI。

| 来源 | 完整提交 |
| --- | --- |
| yijie-contracts | `32dd76298fd5ba2346fe2429f78b2b3e2f32a7e4` |
| yijie-api | `5e97b18cca1492ac29d4a506411d1e7fc70c9628` |
| yijie-coze | `05a81edab974b3041fa3bae27124d7994ca875ff` |

API/Coze/Desktop 消费者锁的 `source_commit` 必须一致指向上表 Contracts；canonical sync 的 `--check` 同时核对该提交内的源、生成物及来源锁。用户已授权创建私有https://github.com/36Dge/yijie-coze.git；Coze origin指向易界，upstream保留原始来源，未向上游推送。

统一真实 D4 仍引用验收当时的候选和构建摘要，见兄弟元仓 FEAT-153/17。此次来源固定改变 Git/锁元数据，九份生成 wire/validator 文件保持原字节。不能复用旧 ignored 运行配置作为新构建登记。

下次运行在正常退出 App/停止栈后，按现有入口重新执行 `make workflow-editor workflow-build workflow-up`；重新生成 editor manifest、provider image 和 authenticated readiness 记录。不得改写旧验收证据或把新构建摘要标成已执行的真实 D4。

本次 Git 交付不启动服务、不迁移或删除数据；原四个卷保留。回退仍为关闭 exact-local 功能并正常停止专用栈，旧 Chat/公开协议保持。
