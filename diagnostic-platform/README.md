# Arthas 在线诊断平台

平台提供授权审批、目标会话、共享 JVM 快照、线程与类方法定位、Watch、Trace、Stack、Monitor、任务事件流及审计。中文工作台支持操作员、审批人和管理员。主机代理使用出站 mTLS、持久回执和本地回收。企业接入包括签名访问令牌、版本化资产同步、工单投递及独立授权的证据引用。

## 构建与健康检查

在 `diagnostic-platform/` 下使用 JDK 17、Maven 3.9 构建。

```bash
mvn -B verify
java -jar platform-api/target/platform-api-0.1.0-SNAPSHOT.jar
# 在另一终端启动
java -jar gateway/target/gateway-0.1.0-SNAPSHOT.jar
curl -fsS http://127.0.0.1:8080/actuator/health
curl -fsS http://127.0.0.1:8081/actuator/health
```

- [外部系统接入](docs/integrations.md)
- [工作台、网关与主机代理部署](docs/pilot.md)
- [平台 OpenAPI](docs/openapi.yaml)
- [执行端接口与网关协议](docs/gateway-contract.md)

控制面默认监听回环地址，使用文件型 H2 保存数据，Flyway 启动时执行迁移。使用 MySQL 8.0 时配置 `SPRING_DATASOURCE_URL`、`SPRING_DATASOURCE_USERNAME`、`SPRING_DATASOURCE_PASSWORD`。角色令牌通过环境变量 `DIAGNOSTIC_ADMIN_TOKEN`、`DIAGNOSTIC_APPROVER_TOKEN`、`DIAGNOSTIC_OPERATOR_TOKEN`、`DIAGNOSTIC_OPERATOR2_TOKEN` 和 `DIAGNOSTIC_EXECUTOR_TOKEN` 分别注入，每项配置独立的高熵令牌。未配置的角色不可访问 API。默认执行端 ID 为 `local-agent`，可用 `DIAGNOSTIC_EXECUTOR_ID` 调整。当前为回环联调配置。

`tools/control-plane-smoke.py` 启动隔离的平台实例与合成应用，验证登记、审批、会话、真实 JVM 快照、端点回收及审计。GitHub Actions 运行动态附着与控制面联调，并单独用 MySQL 8.0 验证迁移和控制面流程。

## 在 Linux 测试主机验证 Arthas

准备 Python 3.11+、同账户的 Java 8 或 Java 17 完整 JDK、批准的 Arthas 4.x ZIP 与包校验值。脚本只启动和诊断本次运行生成的合成应用。每次使用临时目录和随机鉴权凭据。

```bash
python3 tools/arthas-smoke.py \
  --jdk /path/to/target-jdk \
  --arthas-zip /path/to/approved-arthas.zip \
  --sha256 "$ARTHAS_ZIP_SHA256" \
  --classes fixtures/target/classes
```

默认 `attach` 模式验证动态附着，需要目标主机支持 HotSpot Attach 套接字。加 `--mode startup` 可在合成应用启动时加载官方 Arthas Agent，独立验证本地鉴权、快照、异步观测取消和服务退出。启动加载模式仅覆盖上述诊断协议，动态附着仍需在具备 Attach 条件的测试主机单独验证。
