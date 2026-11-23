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
