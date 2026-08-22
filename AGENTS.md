# 概览

LinkSeal 是一个语言无关的可信签名 URL 模板协议，含 JavaScript 与 Java 两个 SDK。

- **协议规范**：`spec/PROTOCOL.md`（数据结构、签名机制、Resolver 流水线、设计决策）
- **构建与测试**：`README.md`

## 不可违反的约束

1. **JS 与 Java 的规范化必须字节级一致。** 两端均遵循 RFC 8785 (JCS)，使用同源参考实现而非各自手写：JS 端 `linkseal/src/canonicalize.ts` 委托 `canonicalize` npm 包，Java 端 `Canonicalizer.java` 委托 `io.github.erdtman:java-json-canonicalization`（类 `org.erdtman.jcs.JsonCanonicalizer`）。改动一端（如升级库版本或改 Java 序列化器）必须同步验证另一端，否则跨语言验签失效。`LinkSealJavaTest.reproducesTheJavascriptSignatureByteForByte` 与 `reproducesExpiringRotatedSignatureByteForByte` 钉住这条约束（后者覆盖 `expiresAt`+`kid` 字段）。Java 端 `JsonCanonicalizer` 只吃 JSON 字符串，故调用方必须注入 `JsonSerializer` 把 `LinkSealProtocol` 转成合法 JSON；SDK 提供 `DefaultJsonSerializer` 作为零依赖参考实现（覆盖 v1 全字段：`version`/`template`/`policy`（含 `defaults`）/可选 `expiresAt`/可选 `kid`），调用方也可注入 Jackson/Gson。**序列化器遗漏的字段不会进入签名覆盖面**，新增协议字段时务必同步更新序列化器（含 `DefaultJsonSerializer`）。`expiresAt` 用 ISO-8601 字符串而非 epoch 数值，以保持 v1 payload 全字符串不变量、避免 RFC 8785 数值格式化的跨语言分歧。

2. **改动规范化会使 `spec/examples/*.signed.json` 失效。** 这些文件的签名需用 `spec/keys/test-private.pem` 重新签发——两端测试都读取它们。`user-profile.signed.json` 是基础 payload（无 `expiresAt`/`kid`）；`expiring-rotated.signed.json` 含 `expiresAt`+`kid`，由 JS signer 签发作为跨语言字节级钉子。重新签发优先用 JS 端 `ProtocolSigner` 生成（保证两端字节一致）。当前 v1 payload 全为 ASCII 字符串，RFC 8785 输出与旧实现字节一致；一旦规范化输出改变（如引入非 ASCII 或数值字段），必须重新签发全部示例。

3. **占位符是意图，不是变量名。** 模板的占位符集合即变量声明全集，不存在额外的声明字段。未解析的变量必须以 null 传递给 Policy Processor，不能从结果中剔除，否则缺失检测失效。理由见 `spec/PROTOCOL.md` §8.1。

4. **两端 TemplateEngine 必须支持同一 RFC 6570 子集、拒绝同一越界集合、并用同一套值编码。** 支持面：`{}`/`{?}`/`{&}`（含逗号分隔多变量）；越界算子（`+#./;`）、explode `*`、prefix `:N` 两端都必须**抛错而非静默展开**。值编码用严格 RFC 3986 unreserved（`A-Za-z0-9-._~` 原样，其余 UTF-8 百分号编码），两端各自手写同一编码器——不委托第三方库，因为 `uri-templates` 等库对 `~ ( ) ' *` 的编码停在 RFC 2396 代际、与 RFC 3986 不一致，两端委托不同库会产生静默字节分歧。子集与编码定义见 `spec/PROTOCOL.md` §4.4–§4.5，钉子是 `TemplateEngineTest` 的 `rejects*` 与 `encodes*` 用例（两端镜像）。

## 环境提示

本机已安装 Maven 3.9.15（JDK 21），`cd java && mvn test` 可直接运行。**测试须在 `java/` 目录下执行**（`SpecFixture` 使用 `../spec/` 相对路径）。Java 端依赖生产库 `io.github.erdtman:java-json-canonicalization:1.1`（已缓存于本地 `~/.m2`）。仅当 Maven 不可用时才回退到 `javac --release 17` + JUnit standalone console jar，需把上述 jar 与 JUnit standalone jar 一并放入 classpath。
