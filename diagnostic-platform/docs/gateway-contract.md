# 网关与主机代理接口

## 已实现的本地联调接口

平台为单个预登记执行端提供受限的拉取接口。执行端身份取自服务端配置的令牌绑定，客户端无法自行提交网区、身份或命令。当前注册与心跳、mTLS 长连接和目标端持久看护由后续工作实现。

| 接口 | 请求与响应 | 行为 |
| --- | --- | --- |
| `POST /api/v1/edge/claims` | 成功返回 `operationId`、`leaseToken`、`targetId`、`fingerprint`、`generation`、`type`、可选 `taskId`、`leaseUntil`、可选 `taskDeadline` | 只领取本执行端的操作。无任务返回 204。时间使用 Unix 毫秒。 |
| `POST /api/v1/edge/operations/{id}/complete` | `leaseToken`、`completion`、可选 `result` | 成功或完全相同的重复结果返回 204。错误凭据、冲突证据及不匹配的领用代次不能改变当前状态。 |

| 操作 | 有效终态证据 |
| --- | --- |
| `ATTACH` | `ATTACHED`、`FAILED`、`TARGET_GONE` |
| `SNAPSHOT` | `DONE`（附结构化 JVM 数值）或 `FAILED` |
| `CANCEL` | `STOPPED` |
| `RELEASE` | `RELEASED`、`TARGET_GONE` |

所有操作都可提交 `UNKNOWN`。平台进入待核对状态，保留活动任务或接入代次，允许该执行端用同一领用凭据补交确认的结果。超时领用不会被自动重派。执行端应在执行前检查指纹、代次和截至时间，只回传已验证的状态。回收以确认 Arthas 停止及端点关闭为准。

## 后续长连接契约

代理通过经批准的连接登记。`agentId`、`hostId`、`zoneId`、`runAccountId` 从可信连接身份映射。目标身份使用主机启动 ID、PID 命名空间、PID 与进程启动 tick。附着前后、调用能力前及释放前复核身份。

| 消息 | 必要字段 | 执行语义 |
| --- | --- | --- |
| Register | agentId、hostId、zoneId、runAccountId、protocolVersion | 双方确认身份、协议和连接代次 |
| Heartbeat | agentId、connectionGeneration、observedAt | 更新连通状态，执行租约独立 |
| Dispatch | operationId、targetId、targetFingerprint、epoch、attachGeneration、deadlineAt、action、授权摘要 | 验证执行权并持久化意图，重复 operationId 返回现有状态 |
| StatusQuery | operationId、targetId、epoch、attachGeneration | 仅查询 |
| ResultEvent | operationId、eventSequence、epoch、attachGeneration、state、result | 回传裁剪后的结果与状态证据 |
| Ack | operationId、eventSequence | 持久化提交后确认 |
