# Arthas 在线诊断平台

首批开发版本包含 Java 17 平台 API 与网关工程、Java 8 字节码诊断样例、Arthas 冒烟检验和首版接口契约。平台和网关当前提供独立启动与健康检查。业务 API、租约调度、持久化和正式主机代理在后续任务实现。

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

- [平台 OpenAPI 草案](docs/openapi.yaml)
- [网关协议草案](docs/gateway-contract.md)

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
