# UniLink Seal Java SDK

UniLink Seal 协议的 Java 参考实现。提供签发方（`ProtocolSigner`）与解析方（`LinkSealCore`），两端 API 表面与 [JavaScript SDK](../javascript/) 镜像，共享同一份[协议规范](../spec/PROTOCOL.md)。

## 环境要求

- Java 17+
- Maven 构建依赖 `java-json-canonicalization`（RFC 8785 JCS），无其他运行时依赖

## 安装

```xml
<dependency>
  <groupId>io.github.xesam</groupId>
  <artifactId>unilink-seal</artifactId>
  <version>0.0.1</version>
</dependency>
```

当前未发布到 Maven Central，可从源码本地安装：

```bash
cd java && mvn install
```

## 密钥格式

UniLink Seal 只接受 **PKCS#8** 编码的 PEM：

- 私钥：`-----BEGIN PRIVATE KEY-----`
- 公钥：`-----BEGIN PUBLIC KEY-----`（即 SPKI）

如果你手握的是 OpenSSL 常见导出的 PKCS#1 格式，需先转换：

```bash
# PKCS#1 私钥 → PKCS#8 私钥
openssl pkcs8 -topk8 -nocrypt -in private.pem -out private.p8.pem

# 由 PKCS#8 私钥导出 SPKI 公钥
openssl rsa -in private.p8.pem -pubout -out public.spki.pem
```

仓库 `spec/keys/` 下的 `test-private.pem` / `test-public.pem` 已是 PKCS#8，可直接用于测试。

## 签发方（服务端）

### 快速开始（零依赖）

```java
import io.github.xesam.unilink.seal.ReferenceJsonSerializer;
import io.github.xesam.unilink.seal.signer.ProtocolSigner;
import io.github.xesam.unilink.seal.model.LinkSealProtocol;
import io.github.xesam.unilink.seal.model.PolicyConfig;
import io.github.xesam.unilink.seal.model.SignedProtocol;

// 构造期注入序列化器（零依赖参考实现）
ProtocolSigner signer = new ProtocolSigner(new ReferenceJsonSerializer());
signer.setPrivateKey(privateKeyPem);  // PKCS#8 PEM 私钥

LinkSealProtocol payload = new LinkSealProtocol(
  "1.0",
  "https://api.example.com/users/{userId}?source=app{&token,locale}",
  new PolicyConfig("error", null),
  null,  // expiresAt (可选)
  null   // kid (可选)
);

SignedProtocol signed = signer.signProtocol(payload);
// { payload, signature } —— 下发给解析方
```

### 生产场景（复用 Jackson）

```java
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
ProtocolSigner signer = new ProtocolSigner(payload -> mapper.writeValueAsString(payload));
signer.setPrivateKey(privateKeyPem);

SignedProtocol signed = signer.signProtocol(payload);
```

### 生产场景（复用 Gson）

```java
import com.google.gson.Gson;

Gson gson = new Gson();
ProtocolSigner signer = new ProtocolSigner(payload -> gson.toJson(payload));
signer.setPrivateKey(privateKeyPem);

SignedProtocol signed = signer.signProtocol(payload);
```

**重要**：序列化器必须覆盖所有协议字段（包括可选字段 `expiresAt` 和 `kid`），否则这些字段不会被签名保护，可被篡改。

## 解析方（客户端）

```java
import io.github.xesam.unilink.seal.LinkSealCore;
import io.github.xesam.unilink.seal.model.SignedProtocol;

// host 白名单构造期强制：签名只证明模板未被篡改，不证明其 host 可信；
// List.of("*") 可显式关闭 host 校验
LinkSealCore resolver = new LinkSealCore(List.of("api.example.com"));
resolver.setPublicKey(publicKeyPem);  // SPKI PEM 公钥

resolver.setVariable("userId", "abc");
resolver.setVariable("token", "t1");
resolver.setVariable("locale", "zh-CN");

String url = resolver.generateUrl(signed);
// https://api.example.com/users/abc?source=app&token=t1&locale=zh-CN
```

`generateUrl` 内部执行：验签 → 过期检查 → 变量解析 → 缺失策略处理 → 模板展开 → URL 安全校验。

### 可选能力

```java
// 密钥轮换：按 kid 注册多把公钥
resolver.setPublicKey("key-2024", publicKeyPemV2);
resolver.setPublicKey("key-2023", publicKeyPemV1);

// 惰性回调：未静态注册的变量名会走回调
resolver.setResolver(name -> {
    if ("token".equals(name)) return fetchToken();
    return null;
});

// 可信 URL 收口：scheme 默认仅 https；host 白名单已在构造期决定，
// setAllowedHosts 用于运行期调整。两个 setter 均不接受 null；
// 关闭校验的唯一方式是显式通配 List.of("*")
resolver.setAllowedSchemes(List.of("https"));
resolver.setAllowedHosts(List.of("api.example.com"));

// 注意：空集合不是"关闭"而是"拒绝一切 host"（fail-closed）；
// 关闭校验的唯一方式是显式通配 List.of("*")，null 会抛错

```

失败以类型化错误抛出：`VerificationException` / `ResolutionException` / `TrustException`（均继承 `LinkSealException`，携带 `code()`），宿主应分支于 `code()` 而非消息文本或异常类名。

### 缺失变量策略

| `missing` | 行为 |
|---|---|
| `"error"` | 变量缺失则抛出 `MISSING_VARIABLE` |
| `"ignore"` | query 位的缺失参数被整个丢弃；简单替换位展开为空字符串（**路径段占位符禁止使用 `ignore`**，会产生退化 URL） |
| `"default"` | 用 `defaults` 中同名值填充 |

```java
LinkSealProtocol payload = new LinkSealProtocol();
payload.setVersion("1.0");
payload.setTemplate("https://api.example.com/users/{userId}{?locale}");
payload.setPolicy(new PolicyConfig("default", Map.of("locale", "zh-CN")));
```

## 包结构

```
src/main/java/io/github/xesam/unilink/seal/
├── Canonicalizer.java           # RFC 8785 JSON 规范化
├── ReferenceJsonSerializer.java # 参考 JSON 序列化实现（零依赖）
├── JsonSerializer.java          # JSON 序列化接口
├── PemKeys.java                 # PEM 密钥解析
├── model/
│   ├── LinkSealProtocol.java   # 协议数据结构
│   ├── SignedProtocol.java     # 签名后的协议
│   ├── PolicyConfig.java       # 缺失变量策略
│   └── MissingPolicy.java      # 策略枚举
├── resolver/
│   ├── LinkSealCore.java       # 解析方编排核心
│   ├── TemplateEngine.java     # RFC 6570 模板展开
│   ├── VariableResolver.java   # 变量注册 + 惰性回调
│   ├── PolicyProcessor.java    # 缺失变量策略处理
│   └── SignatureVerifier.java  # Ed25519 验签
└── signer/
    └── ProtocolSigner.java     # 签发方：私钥签名
```

## 构建与测试

```bash
cd java && mvn test      # 运行测试
cd java && mvn install   # 编译并安装到本地 Maven 仓库
```

## 与 JavaScript SDK 的关系

两端共享同一份[协议规范](../spec/PROTOCOL.md)。跨语言字节级一致性由 `spec/examples/` 下的钉子示例保证——两端测试均读取这些示例，验证对同一 payload 产出完全相同的签名。
