# UniLink Seal

UniLink Seal 是一个语言无关的可信签名 URL 模板协议，附带 JavaScript 与 Java 两份参考实现。

> **定位**：这是一份**协议设计参考实现**，不是要替代 JWT/JWS 的通用签名库。它的价值在于一个明确的协议立场——"占位符是意图、变量由解析方本地提供、跳转策略留给宿主"——以及一份双语言参考实现。协议立场与设计取舍见 [`spec/PROTOCOL.md`](spec/PROTOCOL.md)。

## 目录

1. [背景与目的](#1-背景与目的)
2. [协议角色](#2-协议角色)
3. [快速开始](#3-快速开始)
4. [协议数据结构](#4-协议数据结构)
5. [仓库布局](#5-仓库布局)
6. [构建与测试](#6-构建与测试)
7. [文档](#7-文档)

## 1. 背景与目的

普通的动态拼 URL 不需要签名——后端直接返回完整 URL 即可。UniLink Seal 针对的是另一类场景：

> 解析方要使用远程下发的 URL 模板，但必须确认该模板来自可信签发方且未被篡改，同时模板中的变量只能由解析方本地填充。

典型动机是**移动端/客户端从服务端拉取跳转模板**：客户端拿到一个带占位符的 URL 模板，验签确认它来自可信后端后，用本地持有的值（用户标识、令牌、locale 等）填充占位符，再生成最终 URL 交给宿主跳转。签发方不必知道这些变量的值，解析方也不必信任模板里写死的任何变量内容。

UniLink Seal 在"模板可信"之上额外收口**最终 URL 的可信性**：签名只证明模板字节未被篡改，不证明其 scheme/host 对本解析方安全。SDK 在展开后的最终 URL 上强制校验 scheme（默认仅 `https`）与可选 host 白名单，挡住"签名合法但目标不可信"的情形（签发方私钥泄露、签发方被滥用、或惰性回调返回了不可信 host）。

v1 还支持可选的 `expiresAt`（限制协议有效期，非防重放）与 `kid`（密钥轮换），二者均参与签名覆盖面。完整协议立场、字段取舍与设计决策见 [`spec/PROTOCOL.md` §8](spec/PROTOCOL.md)。

### 1.1 何时不需要 UniLink Seal

以下场景**不需要**签名 URL 模板：

❌ **后端直接返回完整 URL**  
如果后端已知全部变量值（用户 ID、令牌、参数等），直接拼接完整 URL 返回即可，无需模板与签名。

❌ **不需要密码学证明模板来源**  
如果客户端完全信任 HTTPS 通道与后端身份（如自家 App 与自家服务端），签名是多余的——直接下发完整 URL 或 JSON 配置。

❌ **变量由前端从 UI 获取或计算**  
如用户输入搜索词拼接搜索 URL、前端生成时间戳等，直接在前端拼接即可，无需后端下发模板。

❌ **需要归因、短链、跨平台路由**  
Branch.io、Firebase Dynamic Links（已关停）等动态链接平台解决的是「App 下载归因 + 跨平台路由」，与签名模板是正交能力。若核心需求是归因与短链，应使用动态链接平台或短链服务。

✅ **适合 UniLink Seal 的场景**：
- 模板由不完全可信的通道下发（公开 API、CDN 缓存、第三方集成）
- 变量由客户端本地持有（用户标识、会话令牌、设备信息、locale）
- 需要密码学保证模板未被篡改
- 需要在展开后的最终 URL 上强制 scheme/host 白名单（防止私钥泄露或惰性回调注入不可信域名）

**真实场景示例**见 [`docs/use-cases/`](docs/use-cases/)：金融 App 支付跳转、小程序 deeplink、企业 IM 安全跳转。

## 2. 协议角色

协议定义两个独立角色：

- **Signer（签发方）**：构造并签名 URL 模板 payload，预期运行在服务端。持有私钥，只负责生成 payload 与签名，不参与变量解析、模板展开或 URL 执行。
- **Resolver（解析方）**：验证签名、按占位符名解析变量、展开 RFC 6570 URL 模板，返回最终 URL。持有公钥，负责验签、变量填充与可信 URL 收口，但不负责导航执行。

模板中的占位符表达的是**意图**（`{userId}` 即"此处需要一个用户标识"），解析方自行决定如何为每个意图提供值。协议不定义导航目标（WebView、浏览器、deeplink、native route），这些决策与跳转安全策略属于宿主应用。

两角色间的协作流程：

```mermaid
flowchart LR
    S[Signer 签发方] -->|构造 payload + 私钥签名| T[签名 URL 模板]
    T -->|远程下发| R[Resolver 解析方]
    R -->|公钥验签| V{验签通过?}
    V -- 否 --> X[拒绝展开]
    V -- 是 --> E[检查 expiresAt / kid]
    E --> Y[按占位符名解析变量]
    Y --> P[按 policy 处理缺失变量]
    P --> Z[展开 RFC 6570 模板]
    Z --> W{scheme/host 可信?}
    W -- 否 --> N[拒绝最终 URL]
    W -- 是 --> U[返回最终 URL]
```

## 3. 快速开始

两端 SDK 暴露的表面是对称的：Signer 端用 `ProtocolSigner` 签发 `SignedProtocol`，Resolver 端用 `LinkSealCore` 验签并展开。下面以 `https://api.example.com/users/{userId}?source=app{&token,locale}` 模板、`policy.missing = "error"` 为例，展示两端的最小闭环。

### 3.0 密钥与运行环境

> **密钥格式（两端一致）**：UniLink Seal 使用 **Ed25519**，只接受 **PKCS#8** 编码的 PEM——私钥头 `-----BEGIN PRIVATE KEY-----`、公钥头 `-----BEGIN PUBLIC KEY-----`（即 SPKI）。生成新密钥：
>
> ```bash
> # 生成 Ed25519 PKCS#8 私钥
> openssl genpkey -algorithm Ed25519 -out private.pem
> # 由私钥导出 SPKI 公钥（-----BEGIN PUBLIC KEY-----）
> openssl pkey -in private.pem -pubout -out public.spki.pem
> ```
>
> 仓库 `spec/keys/` 下的 `test-private.pem` / `test-public.pem` 已是 Ed25519 PKCS#8，可直接用于测试。若你手握的是 RSA 密钥（`-----BEGIN RSA PRIVATE KEY-----` 等），需改用 Ed25519 重新生成——RSA 不再被支持。
>
> **JS 运行环境**：三个包为 **ESM-only**（`"type": "module"`），仅暴露 `import` 入口、无 CommonJS 产物，要求 **Node.js ≥ 18**（依赖 Web Crypto `crypto.subtle`）。

### 3.1 JavaScript / TypeScript

包名：`unilink-seal`（公共类型 + 规范化）、`unilink-seal-signer`（签发方）、`unilink-seal-resolver`（解析方），位于 `javascript/packages/`，pnpm workspace 内部互相引用。

签发方：

```ts
import { ProtocolSigner } from 'unilink-seal-signer';
import type { LinkSealProtocol } from 'unilink-seal';

const signer = new ProtocolSigner();
await signer.setPrivateKey(privateKeyPem); // PEM 格式 PKCS#8 私钥

const payload: LinkSealProtocol = {
  version: '1.0',
  template: 'https://api.example.com/users/{userId}?source=app{&token,locale}',
  policy: { missing: 'error' },
};

const signed = await signer.signProtocol(payload);
// { payload, signature } —— 下发给解析方
```

解析方：

```ts
import { LinkSealCore } from 'unilink-seal-resolver';
import type { SignedProtocol } from 'unilink-seal';

// host 白名单在构造期强制：签名只证明模板未被篡改，不证明其 host 可信，
// 因此可信 host 边界必须显式决定。传 ['*'] 可显式关闭 host 校验。
const resolver = new LinkSealCore({ allowedHosts: ['api.example.com'] });
await resolver.setPublicKey(publicKeyPem); // PEM 格式公钥

// 静态注册占位符值（也可用 setResolver 注册惰性回调）
resolver.setVariables({
  userId: 'abc',
  token: 't1',
  locale: 'zh-CN',
});

const url = await resolver.generateUrl(signed as SignedProtocol);
// https://api.example.com/users/abc?source=app&token=t1&locale=zh-CN
```

缺失变量处理与值注册的更多细节（`ignore` / `default` 策略、`setResolver` 惰性回调、`clearVariables` 累积语义、`setAllowedSchemes` / `setAllowedHosts`）见 [`spec/PROTOCOL.md` §4–§7](spec/PROTOCOL.md)。

### 3.2 Java

坐标 `io.github.xesam:unilink-seal`，Java 17，Maven 构建。Java 端的 `JsonCanonicalizer` 只吃 JSON 字符串，因此调用方必须注入一个 `JsonSerializer` 把 `LinkSealProtocol` 序列化成合法 JSON——SDK 提供 `DefaultJsonSerializer` 作为零依赖参考实现（已覆盖 v1 全字段），也可注入 Jackson/Gson。**序列化器遗漏的字段不会进入签名覆盖面**，新增协议字段时务必同步更新序列化器。

签发方：

```java
import io.github.xesam.unilink.seal.DefaultJsonSerializer;
import io.github.xesam.unilink.seal.signer.ProtocolSigner;
import io.github.xesam.unilink.seal.model.LinkSealProtocol;
import io.github.xesam.unilink.seal.model.PolicyConfig;
import io.github.xesam.unilink.seal.model.MissingPolicy;
import io.github.xesam.unilink.seal.model.SignedProtocol;

ProtocolSigner signer = new ProtocolSigner();
signer.setPrivateKey(privateKeyPem);      // PEM 格式 PKCS#8 私钥
signer.setJsonSerializer(new DefaultJsonSerializer());

LinkSealProtocol payload = new LinkSealProtocol(
    "1.0",
    "https://api.example.com/users/{userId}?source=app{&token,locale}",
    new PolicyConfig(MissingPolicy.ERROR));

SignedProtocol signed = signer.signProtocol(payload);
// signed.payload() / signed.signature() —— 下发给解析方
```

解析方：

```java
import io.github.xesam.unilink.seal.DefaultJsonSerializer;
import io.github.xesam.unilink.seal.resolver.LinkSealCore;
import io.github.xesam.unilink.seal.model.SignedProtocol;
import java.util.Map;

// host 白名单在构造期强制（与 JS 端语义一致）；List.of("*") 可显式关闭 host 校验。
LinkSealCore resolver = new LinkSealCore(List.of("api.example.com"));
resolver.setPublicKey(publicKeyPem);       // PEM 格式公钥
resolver.setJsonSerializer(new DefaultJsonSerializer());

resolver.setVariables(Map.of(
    "userId", "abc",
    "token", "t1",
    "locale", "zh-CN"));

String url = resolver.generateUrl(signed);
// https://api.example.com/users/abc?source=app&token=t1&locale=zh-CN
```

可选能力：`setPublicKey(kid, keyPem)` 注册多把公钥以支持密钥轮换；`setResolver(Function<String,String>)` 注册惰性回调；`setAllowedSchemes` 调整可信 scheme；`setAllowedHosts` 在运行期调整 host 白名单。两个 setter 均不接受 `null`；关闭校验的唯一方式是显式通配 `["*"]`（host 空列表 = 拒绝一切，scheme 空列表抛配置错误）。两端 API 表面镜像，方法语义一致。

两端均以类型化错误暴露失败原因：JS 端 `LinkSealError` 子类 `VerificationError` / `ResolutionError` / `TrustError`（含 `code` 字段），Java 端 `LinkSealException` 子类 `VerificationException` / `ResolutionException` / `TrustException`（含 `code()`），code 清单两端一致，宿主应分支于 code 而非消息文本，也不要依赖异常类名/`error.name`（JS 端压缩会改变子类名，`code` 不受影响）。

### 3.3 示例文件

`spec/examples/` 提供两个钉子示例，两端测试均读取它们：

- `user-profile.signed.json` — 基础 payload（无 `expiresAt` / `kid`）
- `expiring-rotated.signed.json` — 含 `expiresAt` + `kid`，由 JS signer 签发，作为跨语言字节级一致性钉子

## 4. 协议数据结构

### 4.1 LinkSealProtocol（payload）

```json
{
  "version": "1.0",
  "template": "https://api.example.com/users/{userId}?source=app{&token,locale}",
  "policy": { "missing": "error" }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `version` | string | 协议版本，当前为 `"1.0"` |
| `template` | string | RFC 6570 URL 模板，其占位符即变量声明全集 |
| `policy` | object | 缺失变量处理策略 |
| `expiresAt` | string? | 可选。ISO-8601 过期时间，**必须含时区偏移或 `Z`**；过期则解析方拒绝协议 |
| `kid` | string? | 可选。签名密钥 id，解析方据此选择验签公钥（密钥轮换） |

### 4.2 SignedProtocol（签发方下发格式）

```json
{
  "payload": { "version": "1.0", "template": "...", "policy": { "missing": "error" } },
  "signature": "BASE64_SIGNATURE"
}
```

### 4.3 PolicyConfig

| `missing` | 行为 |
|---|---|
| `"error"` | 变量缺失则抛出 `MISSING_VARIABLE` |
| `"ignore"` | query 位的缺失参数被整个丢弃；简单替换位展开为空字符串（**路径段占位符禁止使用 `ignore`**：会产生 `/users/` 这类退化 URL，生产中路径变量必须用 `error` 或 `default`） |
| `"default"` | 用 `defaults` 中同名值填充，需额外提供 `defaults` 字段 |

```json
{ "missing": "default", "defaults": { "locale": "zh-CN" } }
```

签名为 Ed25519（RFC 8032，确定性签名），规范化遵循 RFC 8785（JSON Canonicalization Scheme），两端使用同源参考实现以保证字节级一致。模板占位符遵循 RFC 6570 的一个受限子集（`{}` / `{?}` / `{&}`，含逗号分隔多变量；越界算子与 `*` / `:N` 修饰符两端均抛错而非静默展开），值编码用严格 RFC 3986 unreserved。完整规则见 [`spec/PROTOCOL.md` §4–§5](spec/PROTOCOL.md)。

## 5. 仓库布局

```text
spec/                         # 协议规范、示例、测试密钥
scripts/                      # 构建与测试脚本
java/                         # Java SDK (Maven, Java 17, JUnit 5)
javascript/                   # JavaScript/TypeScript SDK (pnpm workspace)
  packages/
    unilink-seal/                       # 公共类型 + canonicalize
    unilink-seal-signer/                # ProtocolSigner（服务端）
    unilink-seal-resolver/              # LinkSealCore、SignatureBackend（客户端）
    unilink-seal-crypto-minimal/        # 验签后端：@noble/ed25519（无 Web Crypto 环境 / 小程序，零平台依赖）
```

各包详细说明见 [java/README.md](java/README.md) 和 [javascript/README.md](javascript/README.md)。

行为说明与正确性保证均由两端单元测试承载（Java `mvn test`、JS `pnpm -r test`），不另设可运行示例。两端字节级一致性由 `LinkSealJavaTest.reproducesTheJavascriptSignatureByteForByte` 等跨语言测试钉死。

## 6. 构建与测试

```bash
bash scripts/test.sh                          # 运行两端全部测试

cd javascript && pnpm install && pnpm build   # 构建 JS SDK
cd java && mvn test                           # 仅运行 Java 测试
```

Java 测试须在 `java/` 目录下执行（`SpecFixture` 使用 `../spec/` 相对路径）。

## 7. 文档

- [协议规范](spec/PROTOCOL.md) — 数据结构、签名机制、Resolver 流水线、安全特性、设计决策
- [`AGENTS.md`](AGENTS.md) — 贡献者约束（跨语言规范化一致性、示例重签发流程、模板子集边界）
