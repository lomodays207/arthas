# 网关与主机代理接口草案

代理通过经批准的连接登记。`agentId`、`hostId`、`zoneId`、`runAccountId` 均从可信连接身份映射。平台分配不透明 `targetId`，代理以主机启动 ID、PID 命名空间、PID 与进程启动 tick 核对目标。实现时在附着前后、调用能力前及释放前复核身份。

| 消息 | 必要字段 | 执行语义 |
| --- | --- | --- |
| Register | agentId、hostId、zoneId、runAccountId、protocolVersion | 双方确认身份、协议和连接代次 |
| Heartbeat | agentId、connectionGeneration、observedAt | 更新连通状态，执行租约独立 |
| Dispatch | operationId、targetId、targetFingerprint、epoch、attachGeneration、deadlineAt、action、授权摘要 | 先验证执行权并记录操作意图。重复 operationId 返回现有状态 |
| StatusQuery | operationId、targetId、epoch、attachGeneration | 查询目标侧状态和已记录结果，不重复执行 |
| ResultEvent | operationId、eventSequence、epoch、attachGeneration、state、result | 回传裁剪后的结果和状态证据 |
| Ack | operationId、eventSequence | 中心持久化提交后确认 |

`action` 预留 `PREFLIGHT`、`ATTACH`、`SNAPSHOT`、`START_TASK`、`CANCEL_TASK` 和 `RELEASE`。诊断能力由类型化目录映射。一个 JVM 同时只占用一个动态任务槽。派送结果未知进入 `RECONCILING`。中断确认、底层终态和端点关闭是不同的状态证据，中心逐项检查后再释放对应资源。
