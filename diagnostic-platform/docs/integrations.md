# 外部系统接入

## 身份和审批

平台可验证身份提供方签发的 RS256 访问令牌。配置 DIAGNOSTIC_SSO_PUBLIC_KEY 为本地可信 RSA 公钥 PEM 文件、DIAGNOSTIC_SSO_ISSUER 为签发者、DIAGNOSTIC_SSO_AUDIENCE 为本平台受众，DIAGNOSTIC_SSO_SUBJECTS 以逗号分隔 `subject=OPERATOR`、`subject=APPROVER` 等绑定。令牌须包含有效期。操作员用户标识为 `sso.subject`，资产成员清单使用此标识。企业门户取得访问令牌后可作为 Bearer 调用 API。公钥轮换通过版本化配置发布。当前实现没有企业门户登录重定向页面。

审批系统使用 APPROVER 身份调用授权决策接口。eventId 应采用审批侧稳定事件编号。expectedRevision、decision、reasonCode 用于冲突检测和审计。APPROVE、DENY 和 REVOKE 均有重放检查。外部告警/APM 使用工作台的 asset、target、ticket 参数做上下文跳转。身份提供方、外部审批、告警字段映射需要实际环境配置。

## CMDB

同步器使用管理身份调用 `PUT /api/v1/inventory/assets/{assetId}`，提交完整的资产记录及资产内单调递增的 sourceRevision。

```json
{
  "sourceRevision": 18,
  "active": true,
  "asset": {
    "assetId": "sample-vm", "appId": "sample-app", "environmentName": "test",
    "zoneId": "zone-a", "agentId": "sample-agent", "displayName": "Sample JVM host",
    "members": ["sso.sample"]
  }
}
```

相同版本及内容可以重试。旧版本、同版本不同内容会返回冲突。移除成员撤销其受影响的授权。停用资产会撤销全部在途授权并退役旧目标。变更网区、应用、环境或代理前须先排空原路由，仍有接入或在途任务时返回 DRAIN_BEFORE_MOVE，不能把清理请求转给新代理。迁移后重新登记候选 JVM，保留原目标审计。

## ITSM 与智能体证据

平台创建或撤销证据引用时，在同一事务写入工单投递队列。工单侧接收 JSON 字段 sequenceNo、eventId、eventType、referenceId、ticketId 和 occurredAt。接收端须以 eventId 去重，成功持久化后返回 2xx。平台重试时复用同一 Idempotency-Key。授权撤销或到期后即使外部工单仍显示旧引用，读取也会被拒绝。

运行 `python3 tools/ticket-forwarder.py`，配置 DIAGNOSTIC_PLATFORM_URL、DIAGNOSTIC_ITSM_URL、DIAGNOSTIC_ITSM_TOKEN、ITSM_RECEIVER_TOKEN。私有 CA 可通过 DIAGNOSTIC_CA_FILE 指定。DIAGNOSTIC_ITSM_TOKEN 需同时配置在平台和转发器。该身份只能领取工单事件和确认交付。接收侧如采用其他工单协议，需要在接收端转换为实际接口。可用 `--once` 处理一批并退出。

运维系统或智能体读取证据时携带实际委托用户的访问令牌，引用必须指定该用户，且该用户仍需具备独立的目标和能力授权。审计保留读取人身份。当前没有开放可绕过用户授权的智能体代发任务身份。

## 网区和网关

每个网区可部署多台网关，代理配置 gateways 数组提供最多四个 HTTPS 入口。每个入口独立验证服务证书，持有该网区对应代理的证书绑定，指向共享同一事务数据库的控制面。链路失败时，代理切换到下一个已配置入口，已有操作使用同一编号回执。管理接口 `GET /api/v1/management/zones` 返回当前修订号，`PUT /api/v1/management/zones/{id}` 以 paused 和 expectedRevision 暂停或恢复全区新增诊断。查询、取消与回收继续运行。实际网区隔离、多节点切换与数据库 HA 需要在部署拓扑验收。
