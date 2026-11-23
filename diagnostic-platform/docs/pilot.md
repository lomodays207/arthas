# Linux 单目标部署与验证

## 组件与配置

中心与网关在同一台机器运行，平台默认使用回环端口 8080。用 Java 17 和 Maven 3.9 执行 `mvn -B verify`。在平台进程注入管理员、审批人、操作员令牌，分别对应 `DIAGNOSTIC_ADMIN_TOKEN`、`DIAGNOSTIC_APPROVER_TOKEN`、`DIAGNOSTIC_OPERATOR_TOKEN`。令牌使用独立随机值。资产登记使用管理 API，成员字段填写有权操作的身份。浏览器通过本机或 SSH 端口转发访问 `http://127.0.0.1:8080/console.html`。

中心使用 `DIAGNOSTIC_AGENT_TOKENS` 配置逗号分隔的 `agent-id=token`，每个代理身份配置一个随机令牌。网关使用 `DIAGNOSTIC_CERT_TOKENS` 配置逗号分隔的 `leaf-sha256=token`，令牌与中心登记值对应。指纹为 DER 证书的 64 位小写十六进制 SHA-256，可用以下命令计算。

```sh
openssl x509 -in agent.pem -outform DER | openssl dgst -sha256
```

在网关设置 `SERVER_ADDRESS` 为代理可达的监听地址，设置 `SERVER_SSL_ENABLED=true`、`SERVER_SSL_CERTIFICATE`、`SERVER_SSL_CERTIFICATE_PRIVATE_KEY`、`SERVER_SSL_TRUST_CERTIFICATE` 为对应的服务证书、私钥和代理 CA 文件。服务证书 SAN 应匹配代理访问的域名或 IP，代理证书用于客户端鉴权。通过服务管理器分别启动平台和网关 JAR。新增代理或轮换证书时同步更新两端绑定并重启。代理仅需自己的客户端证书、私钥和服务 CA。

## 目标主机

主机使用 Linux、Python 3.11+ 和与目标 JVM 匹配的完整 JDK，以应用账户运行。一个代理身份和私有状态目录绑定一个明确登记的目标。先运行以下命令取得 PID 和进程指纹。管理员通过资产 API 登记 targetId、fingerprint、javaFeature，并将所属资产绑定到此代理身份。

```sh
python3 agent/host_agent.py --discover /opt/target-jdk
```

在应用账户专属目录中准备配置，替换各项路径和示例值。介质使用经过核验的 Arthas 4.3.5 离线包。配置和证书路径建议使用绝对路径。

```json
{
  "gateway": "https://gateway.example:8081",
  "ca": "/opt/diag/ca.pem", "cert": "/opt/diag/agent.pem", "key": "/opt/diag/agent.key",
  "targetId": "sample-jvm", "pid": 12345, "fingerprint": "linux:<discovered-hash>",
  "jdk": "/opt/target-jdk", "archive": "/opt/diag/arthas-4.3.5.zip",
  "sha256": "2f75ea954ead5d02c4a743ecd783fd92f546a44ef3aee437ea5066eb30ad07bf",
  "stateDir": "/var/tmp/sample-agent"
}
```

运行 `python3 agent/host_agent.py --config /opt/diag/agent.json`。工作台用操作员身份选择目标、关联工单并申请权限。审批人在独立浏览器会话批准后，操作员刷新授权记录、打开工作区、采集快照。管理员可查询目标审计。退出工作区会触发空闲回收。

代理将操作意图和回执写入 SQLite，再进行派送应答。已确定同一代次的本地回收会在重连后上报中心。连续网关通信失败超过 45 秒会尝试关闭本代理拥有的端点。未能核实终态的操作保留 UNKNOWN 并需要核对。服务管理器应在代理崩溃后重新拉起进程，同一状态目录只允许一个实例。JVM 重启后重新发现指纹并登记新的目标和状态目录。当前单目标模式使用独立的代理身份，目标选择与权限由中心和主机共同约束。

## 验证

`tools/gateway-smoke.py` 生成临时 CA 及三个客户端证书，启动真实平台和网关，验证双向认证、证书绑定、跨代理拒绝、重复回执及代次回收。提供 `--jdk --archive --classes` 时，脚本还会启动独立主机代理和样例 JVM，验证真实动态附着、快照和代理重启后回收对账。完整参数见 CI 工作流。

## 线程、类和方法诊断

工作台支持按能力申请授权。线程列表返回热点线程 ID、状态与 CPU 百分比；线程详情按 ID 读取裁剪后的堆栈。使用类方法定位时输入完整类名和精确方法名，可查到加载器哈希及重载描述符。四类方法诊断都要求选择具体加载器，相同方法名的重载均属于观测范围。主机配置需显式填写本地批准的方法，例如 `"allowedMethods":["example.orders.OrderService#submit"]`。Watch 返回耗时与正常或异常出口；Trace 返回带深度和耗时的节点；Stack 返回调用者堆栈；Monitor 返回一个短窗口内成功数、失败数及平均耗时。数据表最多十二行，无命中和截断分别显示。主机只执行固定命令模板及固定表达式。

## 管理、引用与告警跳转

管理员可查看每个已登记代理的最近领取时间、在线状态和待回收目标。读取实例策略后可暂停新增诊断，或修改每个 JVM 同时可开的会话数。修改带版本号，已有任务仍可取消或回收。外部告警页面可以使用 `/console.html?asset=sample&target=sample-jvm&ticket=demo` 打开工作台；选项取自当前登录人可见的资产，审批与附着仍使用正常流程。

操作员可将已完成任务的结果共享给指定的资产成员。引用接收人须持有同一目标和能力的有效授权。引用有独立截止时间，创建人和管理员可以撤销。读取、共享、撤销均记录审计。集成方可通过授权 API 读取引用，远端 ITSM 工单的写入需要部署方配置受信任的工单连接。

## 发布及回退

在 Maven 构建通过后运行 `python3 tools/package-pilot.py --out target/diagnostic-pilot.zip`。解压到独立版本目录，执行 `sha256sum -c SHA256SUMS`，通过 `sh run.sh platform`、`sh run.sh gateway`、`sh run.sh agent --config /opt/diag/agent.json` 分别启动。服务管理器负责传入各自身份及环境变量，并配置重启。数据目录、数据库连接配置和代理日志目录应位于版本目录之外。升级前暂停新增任务，等待接入回收、备份数据库与代理状态。回退到兼容旧版本；存在不兼容数据库变更时，先在隔离环境验证备份恢复，避免覆盖新写入的数据。

## 共享采样和故障演练

对已授权会话调用 `POST /api/v1/sessions/{id}/overview` 会合并同一 JVM、同一代次正在执行的快照，并可复用五秒内收到的结果。调用 `GET /api/v1/sessions/{id}/overview` 只读取状态。响应包含 generation、receivedAt、stale 和 pending。任务 SSE 接口 `GET /api/v1/tasks/{id}/events` 支持 Last-Event-ID 重连，从数据库恢复后续状态，每批复核授权。最终的结果仍通过任务查询获取。

在网关端到端测试中增加 `--network-loss` 会实际暂停网关进程，检查代理在本地超时后关闭样例 JVM 监听器，并在网关恢复后提交回收证据。持续任务的采集窗口受硬期限限制。部分 Java 8 Trace 事件仅返回线程根节点，工作台将这样的结果标为部分结果。

## 合成性能与现场留存验证

`tools/fixture-performance.py` 对同一合成 JVM 先运行空闲诊断基线，再开启周期快照。每阶段报告单核 CPU 使用率、业务批次 P95 中的最大值、交易次数和采样耗时。参数为 `--jdk --archive --classes --seconds`，默认动态附着，每阶段默认 20 秒。基线包含已加载的 Arthas。这个试验不能给出真实业务准入结论。

`tools/fixture-experiments.py` 在脚本新建的合成 JVM 中执行两秒 wall 剖析、一次调用现场留存，校验生成物非空，并核对产物和留存条目已经删除。接口层没有暴露留存对象、产物文件和重放入口。使用与性能脚本相同的 JDK、介质及样例目录参数。
