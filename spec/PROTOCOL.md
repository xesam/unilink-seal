# LinkSeal v1 协议规范

## 一、项目定位

LinkSeal 是一个**可信动态链接模板协议**，解决的核心问题是：**解析方如何安全信任签发方下发的 URL 模板协议**。

普通的动态拼 URL 不需要签名——后端直接返回完整 URL 即可。LinkSeal 针对的是另一类场景：

> 解析方要使用远程下发的 URL 模板，但必须确认该模板来自可信签发方且未被篡改，同时模板中的变量只能由解析方本地填充。

核心流程：

```text
Protocol Payload + Signature
        ↓
   Resolver Verify
        ↓
 Resolve Variables
        ↓
   Expand Template
        ↓
     Final URL
```

---

## 二、系统职责划分

LinkSeal 定义两个独立角色：

| 角色 | 负责 | 不负责 |
|---|---|---|
| Signer | 生成 payload、用私钥签名 | 变量解析、模板展开、URL 执行 |
| Resolver | 公钥验签、解析变量、展开模板、生成 URL | 导航执行（WebView/浏览器/deeplink）、宿主安全策略 |

**Signer 签协议，Resolver 验协议，验签通过后填充变量生成 URL。**

协议分层，签名验证是可信性的根：

```
+----------------------+
| Template Layer       |
+----------------------+
| Policy Layer         |
+----------------------+
| Signature Verify     |  ← 协议可信性的根
+----------------------+
```

宿主应用负责决定最终 URL 如何使用（WebView、native route、deeplink、外部浏览器），以及跳转前的宿主安全策略（域名白名单、WebView 权限、Cookie 策略等）。这个边界保持了协议简单，避免把宿主跳转策略塞进协议。

---

## 三、协议数据结构

### 3.1 LinkSealProtocol（payload）

```json
{
  "version": "1.0",
  "template": "https://x.y.z/more?userId={userId}",
  "policy": {
    "missing": "error"
  }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `version` | string | 协议版本，当前为 `"1.0"` |
| `template` | string | RFC 6570 URL 模板，其占位符即变量声明 |
| `policy` | object | 缺失变量处理策略 |
| `expiresAt` | string? | 可选。ISO-8601 过期时间，**必须含时区偏移或 `Z`**（如 `"2099-12-31T23:59:59Z"`）。解析方在当前时间超过该瞬间时拒绝协议。用字符串而非 epoch 数值，以保持 v1 payload 全字符串不变量、避免 RFC 8785 数值格式化的跨语言分歧（见 §5.2） |
| `kid` | string? | 可选。签名密钥 id，用于密钥轮换。解析方据此选择验签公钥（见 §5.3） |

### 3.2 SignedProtocol（签发方下发格式）

```json
{
  "payload": { "...LinkSealProtocol..." },
  "signature": "BASE64_SIGNATURE"
}
```

- `payload`：协议内容
- `signature`：对 payload 的数字签名，保证完整性与来源可信

### 3.3 PolicyConfig

| 策略 | 行为 |
|---|---|
| `"error"` | 变量缺失则抛出错误 `MISSING_VARIABLE` |
| `"ignore"` | 从变量表中省略缺失变量：query 位（`{?}`/`{&}`）的参数被整个丢弃；简单替换位（`{var}`）展开为空字符串。注意：对路径段占位符用 `ignore` 会产生退化 URL（如 `/users/{userId}` → `/users/`），生产中路径变量应使用 `error` 或 `default` |
| `"default"` | 使用 `defaults` 中提供的默认值填充 |

`"default"` 模式下需额外提供 `defaults` 字段：

```json
{
  "missing": "default",
  "defaults": {
    "locale": "zh-CN"
  }
}
```

### 3.4 协议字段清单

v1 版本包含：`version`、`template`、`policy`、可选的 `expiresAt`、可选的 `kid`，以及外层的 `signature`

v1 版本明确**不包含**：

- `context`（模板变量到解析方变量的映射表）——理由见 §八
- `target`、WebView/浏览器/deeplink/native route 执行策略、跳转确认弹框、客户端导航执行器

---

## 四、模板与占位符

**占位符是意图，不是变量名。**

模板中的 `{userId}` 表达的是"此处需要一个用户标识"这一意图。解析方内部是否存在同名变量、值从哪里取得（内存、数据库、实时计算），完全属于解析方的实现细节，协议不作规定也不感知。

```
https://api.example.com/users/{userId}?source=app{&token,locale}
```

上面的模板声明了三个意图：`userId`、`token`、`locale`。

### 4.1 变量声明来自模板

模板的占位符集合**即**该协议声明的变量全集。解析方通过解析模板得到这个集合，并以它为基准判断变量是否缺失——不存在额外的声明字段。

### 4.2 解析方职责

解析方负责为每个意图提供值。SDK 提供两种注册方式：

- **静态注册** — 直接按占位符名提供值
- **惰性回调** — 注册一个 `(name) => value | null` 的回调，在需要时按名求值，适合令牌刷新、时间戳生成等场景

**静态注册优先**：某个占位符已被静态注册时，回调不会为它触发。两者都未提供值即视为缺失。

**静态注册会累积且不自动清除**：`setVariables` 合并写入、不删除；未声明的 stale 变量因不会被当前模板读取而无害，但已注册的值会持续遮蔽回调。需要让回调重新接管某个意图（如令牌从静态值切回刷新回调）时，调用 `clearVariables()` 清空全部静态注册后再按需重设。跨 `generateUrl` 调用复用同一 Resolver 实例时注意此累积语义。

解析方只暴露自己愿意暴露的意图。远程模板无法要求解析方提供未实现的意图——未实现即缺失，由 `policy` 决定后果。

### 4.3 Query 参数规则

按 RFC 6570：

- `{?var}` 用于**开始** query string，生成 `?var=value`
- `{&var}` 用于**追加** query string，生成 `&var=value`

模板中没有固定 query 参数时使用 `{?}`：

```
https://example.com/users/{userId}{?token,locale}
```

模板中已有固定 query 参数时应使用 `{&}` 追加：

```
https://example.com/users/{userId}?source=app{&token,locale}
```

**不推荐**在已有 `?` 的模板中使用 `{?}`——这会产生第二个 `?`，通常不是期望的 query 结构：

```
https://example.com/users/{userId}?source=app{?token}
```

### 4.4 支持的 RFC 6570 子集

两端 SDK **只支持 RFC 6570 的一个子集**，而非完整 Level 4：

| 表达式 | 含义 | 支持 |
|---|---|---|
| `{var}` / `{a,b}` | 简单替换（Level 1），逗号分隔多变量 | ✅ |
| `{?var}` / `{?a,b}` | form-style query 起始 | ✅ |
| `{&var}` / `{&a,b}` | form-style query 续接 | ✅ |
| `{+var}` `{#var}` `{.var}` `{/var}` `{;var}` | 保留/片段/标签/路径/路径参数展开 | ❌ 拒绝 |
| `{var*}` 爆炸修饰符 | explode | ❌ 拒绝 |
| `{var:N}` 前缀修饰符 | prefix | ❌ 拒绝 |

变量名仅允许 `[A-Za-z0-9_.]`。**遇到子集外的算子或修饰符，两端 SDK 都会抛错而非静默展开**——两端手写同一子集而非各自委托不同库，是为了避免"库冻结在不同 URI 字符集代际"导致的静默字节分歧（见 §4.4 末段）。协议的用例只需要简单替换与 form-style query，因此把支持面收窄到这个子集，并在越界时明确失败。

### 4.5 值编码

变量值按严格 RFC 6570 编码，即 RFC 3986 "unreserved"：`A-Za-z0-9-._~` 原样保留，其余每个字节按 UTF-8 百分号编码（大写十六进制）。该规则对三个支持算子（`{}`/`{?}`/`{&}`）一致。两端 SDK 各自手写同一个编码器，并以 `TemplateEngineTest` 的 `encodes*` 用例镜像钉死字节一致——不依赖第三方库，因为现成库对 `~ ( ) ' *` 等字符的编码分歧于 RFC 3986 代际更替（RFC 2396 曾把 `!~*'()` 列为 unreserved，RFC 3986 收窄为 `-._~`，库各自停留在不同代际）。

---

## 五、签名机制

### 5.1 目标

确保解析方可以验证：

1. 协议来自可信签发方
2. 协议未被篡改

### 5.2 算法

当前 v1 使用 **RSA-SHA256**。

签名前需对 payload 进行**规范化（canonicalization）**——将 payload 序列化为稳定的字节串。规范化必须**递归覆盖所有层级**，包括 `policy` 及其 `defaults` 的全部内容；任何未纳入规范化的字段都不受签名保护，可被篡改而不被发现。

**规范化遵循 [RFC 8785 (JSON Canonicalization Scheme)](https://www.rfc-editor.org/rfc/rfc8785)**。两端 SDK 使用同一规范的同源参考实现，而非各自手写：JavaScript 端用 [`canonicalize`](https://www.npmjs.com/package/canonicalize)，Java 端用 [`java-json-canonicalization`](https://github.com/erdtman/java-json-canonicalization)，二者均由 RFC 8785 作者维护。具体规则（键按 Unicode 码点升序递归排序、无多余空白、`undefined` 键忽略、字符串按 JSON 转义、非有限数值报错、最终 UTF-8 编码）以 RFC 8785 为准。

各语言 SDK 必须对同一 payload 产出**字节级一致**的规范化结果，否则跨语言验签会失败。v1 payload 全为字符串、不含数值字段；两端库对数值的格式化在边界情形（极大/极小、精度）可能不同，协议在引入数值字段前需补充跨语言用例钉死。

示例（`policy` 的内容参与签名）：

```text
{"policy":{"missing":"error"},"template":"https://api.example.com/users/{userId}?source=app{&token,locale}","version":"1.0"}
```

签发方：`signature = RSA-SHA256.Sign(privateKey, canonicalPayload)`

解析方：`RSA-SHA256.Verify(publicKey, payload, signature)`

后续版本可考虑迁移至 **Ed25519**（更快、更短签名、更易于解析方实现），届时通过 `version` 字段区分算法。

### 5.3 密钥管理

- 签发方持有私钥，负责签名
- 解析方持有公钥，负责验签
- 公钥应由可信渠道分发，不能无条件信任与协议同一通道下发的公钥
- 密钥轮换：payload 携带可选 `kid` 标识签发所用密钥；解析方按 `kid` 选择对应公钥验签。未携带 `kid` 的协议用解析方配置的默认公钥。`kid` 参与签名覆盖面，篡改 `kid` 会导致验签失败

---

## 六、Resolver 执行流水线

### 6.1 模块划分

```
LinkSeal Resolver
 ├── Protocol Parser      # 解析 payload + signature
 ├── Signature Verifier   # 验签
 ├── Template Engine      # 提取占位符名 / 展开 RFC 6570 模板
 ├── Variable Resolver    # 按占位符名取值
 └── Policy Processor     # 处理缺失变量策略
```

### 6.2 执行步骤

1. **Parse** — 将 `SignedProtocol` 拆分为 `payload` 和 `signature`
2. **Verify Signature** — 规范化 payload，用公钥验签。失败则拒绝执行
3. **Extract Variables** — 从 `template` 中提取占位符名，得到已声明变量全集
4. **Resolve Variables** — 为每个占位符名取值
5. **Apply Policy** — 根据 `policy.missing` 处理未解析的变量
6. **Expand Template** — 用解析后的变量展开 RFC 6570 URL 模板

### 6.3 各模块详述

**Signature Verifier**

输入：payload + signature；执行：`Verify(public_key, payload, signature)`；通过则继续，失败返回 `INVALID_SIGNATURE` 并拒绝执行。

**Template Engine**

两个职责：

1. **提取占位符名** — 从模板中解析出变量全集，作为缺失判断的基准。同名占位符多次出现只计一次
2. **展开** — 输入模板和变量映射，输出完整 URL。例如 `https://api.example.com/users/{userId}` + `{"userId":"abc"}` → `https://api.example.com/users/abc`

**Variable Resolver**

按占位符名取值，优先查静态注册的值，未命中再调用惰性回调（若已注册）。

**未能解析的变量必须保留为空值（null）而非从结果中剔除**，否则 Policy Processor 无法区分"变量无值"与"变量未声明"，缺失变量检测会失效。解析方不应提供任何内置的占位默认值——宿主未注册值时应表现为缺失，而不是静默生成含假值的 URL。

**Policy Processor**

以模板声明的变量全集为基准判断缺失：值为空的变量即为缺失。

| 策略 | 行为 |
|---|---|
| `error` | 存在缺失变量则抛出 `MISSING_VARIABLE` |
| `ignore` | 从变量表中省略缺失变量：query 位的参数被丢弃，简单替换位的占位符展开为空字符串（不保留 `{...}` 字面量） |
| `default` | 用 `defaults` 中同名的值填充；无同名默认值的仍记为缺失 |

已解析出的值优先于 `defaults`。`defaults` 仅在 `default` 策略下生效。

---

## 七、安全特性

LinkSeal 提供三项安全保证：

1. **协议可信性**：模板来自持有私钥的可信签发方
2. **协议完整性**：模板在传输过程中未被篡改
3. **可信 URL 收口**：签名只证明模板未被篡改，不证明其 scheme/host 对本解析方安全。SDK 在**展开后的最终 URL** 上强制校验 scheme 与 host，挡住"签名合法但目标不可信"的情形——签发方私钥泄露、签发方本身被滥用、或惰性回调返回了不可信 host（变量可填 host 位，如 `https://{host}/...`）。

Resolver 的信任校验由 `LinkSealCore` 内置，无需宿主另行实现：

- **scheme 默认强制**：仅允许 `https`。可通过 `setAllowedSchemes` 扩展（如内网 `http`、deeplink 自定义 scheme），或传 `null` 关闭（仅测试用）。
- **host 白名单 opt-in**：默认不校验 host；通过 `setAllowedHosts` 配置后才启用，按 hostname（不含端口）匹配。
- 校验在**展开后的 URL** 上执行，因此变量填入 host 位的情形也在覆盖范围内。

宿主仍负责签名之外的跳转执行安全（WebView 权限、Cookie 策略、跳转确认等）。

关于变量读取范围：解析方只为自己主动注册的占位符提供值，远程模板无法要求解析方暴露未实现的意图。读取边界由解析方注册了什么决定，不需要协议层的白名单字段。

> **生产化提示**：v1 支持可选的 `expiresAt`（防重放）与 `kid`（密钥轮换），二者均参与签名覆盖面，篡改即验签失败。未携带 `expiresAt` 的协议签名长期有效，签发方应按风险决定是否设置过期。scheme/host 校验已由 SDK 默认/可选强制，无需宿主重复实现。

---

## 八、设计决策

### 8.1 为何不包含 `context`

早期设计中 payload 含一个 `context` 字段，把模板变量名映射到 `$domain.key` 表达式（如 `userId: "$user.id"`）。该字段已移除，理由如下。

**它并未提供它看起来提供的东西。** `$domain.key` 的措辞暗示"签发方引用解析方的变量路径"，但解析方从不反射自身内存——它只能读到宿主主动发布的值。"能读到什么"始终由解析方控制，映射表并未赋予签发方任何实际的读取能力，只是让两边共享了一套名字。

**占位符是意图，不是变量名。** 既然 `{userId}` 表达的是意图、而解析方自己知道该意图对应什么，就不需要一张表来声明这层对应关系。变量全集改由模板的占位符集合推导，少一个字段、少一处签名覆盖面，也少了一类"模板里有但 `context` 没声明"的不一致状态。

**代价是参数名与意图名绑定。** RFC 6570 的 query 操作符中参数名即变量名，`{&token}` 只能产出 `token=`；`context` 曾经可以把对外参数名与本地意图名解耦。这不是遗留的技术债，而是上述立场的直接结论：**即便未来要对接参数名由第三方规定的服务，也不应重新引入映射表。** 「`uid` 在我们这儿叫 `userId`」是对接方对自身命名的认知，该由对接方自己识别和解析。

把这层映射写进 payload 会造成三重损失：协议里出现只对某一个外部服务成立的知识；同一份模板对不同对接方需要不同映射表，签发方被迫了解每个下游的命名习惯；而这张表并不带来新能力——对接方在自己边界内做同样能做，且改名时无需重新签发。因此参数名分歧应在协议之外消解。

### 8.2 为何不包含 `target`

`target` 字段（WebView/browser/deeplink/native route）属于跳转执行层面的决策，不属于"可信 URL 生成"的内核。v1 的输出是**可信 URL 字符串**，怎么使用完全由宿主决定。

### 8.3 为何保留 `policy`

`missing: "error"` 与命名权无关，因此不随 `context` 一起失效：签名保证模板未被篡改，但保证不了解析方**认得**模板里的占位符。老版本客户端拿到含新占位符的模板时，签发方需要能要求它明确失败，而不是静默产出一个缺参数的 URL 并跳转过去。
