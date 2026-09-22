# UniLink Seal JavaScript SDK

UniLink Seal 协议的 JavaScript / TypeScript 参考实现。提供签发方（`unilink-seal-signer`）与解析方（`unilink-seal-resolver`），两端 API 表面与 [Java SDK](../java/) 镜像，共享同一份[协议规范](../spec/PROTOCOL.md)。

## 环境要求

- Node.js ≥ 18（签发方、默认验签后端依赖 Web Crypto `crypto.subtle`）
- TypeScript ≥ 5.3
- pnpm（workspace 管理）

所有包为 **ESM-only**（`"type": "module"`），仅暴露 `import` 入口。

## 包结构

```
packages/
├── unilink-seal/                       # 公共基础：类型定义 + RFC 8785 规范化
├── unilink-seal-signer/                # 签发方（服务端）：Ed25519 签名
├── unilink-seal-resolver/              # 解析方（客户端）：验签 + 模板展开 + URL 安全校验
└── unilink-seal-crypto-minimal/        # 验签后端备选：@noble/ed25519（无 Web Crypto 环境 / 小程序）
```

### 各包职责

| 包 | 定位 | 关键依赖 |
|---|---|---|
| `unilink-seal` | 共享类型 + RFC 8785 JSON 规范化 | `canonicalize`（1.3KB，纯 JS） |
| `unilink-seal-signer` | 服务端签发：Ed25519 私钥签名 | `crypto.subtle`（Node.js / 浏览器） |
| `unilink-seal-resolver` | 客户端解析：验签编排 + RFC 6570 模板展开 + 变量解析 + 策略处理 | 默认用 `crypto.subtle`，可通过接口注入替代后端 |
| `unilink-seal-crypto-minimal` | `SignatureBackend` 实现，用 `@noble/ed25519` 替代 `crypto.subtle`（无平台 API 依赖） | `@noble/ed25519` + `@noble/hashes` |

## 密钥格式

UniLink Seal 使用 **Ed25519**，只接受 **PKCS#8** 编码的 PEM：

- 私钥：`-----BEGIN PRIVATE KEY-----`
- 公钥：`-----BEGIN PUBLIC KEY-----`（即 SPKI）

```bash
# 生成 Ed25519 PKCS#8 私钥
openssl genpkey -algorithm Ed25519 -out private.pem

# 由私钥导出 SPKI 公钥
openssl pkey -in private.pem -pubout -out public.spki.pem
```

仓库 `spec/keys/` 下的 `test-private.pem` / `test-public.pem` 已是 Ed25519 PKCS#8，可直接用于测试。RSA 密钥不再被支持。

## 签发方（服务端）

```ts
import { ProtocolSigner } from 'unilink-seal-signer';
import type { LinkSealProtocol } from 'unilink-seal';

const signer = new ProtocolSigner();
await signer.setPrivateKey(privateKeyPem);  // PKCS#8 PEM 私钥

const payload: LinkSealProtocol = {
  version: '1.0',
  template: 'https://api.example.com/users/{userId}?source=app{&token,locale}',
  policy: { missing: 'error' },
};

const signed = await signer.signProtocol(payload);
// { payload, signature } —— 下发给解析方
```

签发方依赖 `crypto.subtle`、`TextEncoder`、`atob`/`btoa`，仅在 Node.js ≥ 18 或浏览器中运行。

## 解析方（客户端）

### 浏览器 / Node.js 环境

默认使用内置的 `WebCryptoSignatureBackend`（零第三方依赖）：

```ts
import { LinkSealCore } from 'unilink-seal-resolver';
import type { SignedProtocol } from 'unilink-seal';

// host 白名单构造期强制：签名只证明模板未被篡改，不证明其 host 可信；
// ['*'] 可显式关闭 host 校验
const resolver = new LinkSealCore({ allowedHosts: ['api.example.com'] });
await resolver.setPublicKey(publicKeyPem);  // SPKI PEM 公钥

resolver.setVariables({
  userId: 'abc',
  token: 't1',
  locale: 'zh-CN',
});

const url = await resolver.generateUrl(signed as SignedProtocol);
// https://api.example.com/users/abc?source=app&token=t1&locale=zh-CN
```

`generateUrl` 内部执行：验签 → 过期检查 → 变量解析 → 缺失策略处理 → 模板展开 → URL 安全校验。

### 小程序环境

小程序中没有 `crypto.subtle`，需注入替代验签后端：`unilink-seal-crypto-minimal`。

**`unilink-seal-crypto-minimal`（推荐）**

```ts
import { LinkSealCore } from 'unilink-seal-resolver';
import { MinimalSignatureBackend } from 'unilink-seal-crypto-minimal';

const resolver = new LinkSealCore({
  allowedHosts: ['api.example.com'],
  signatureBackend: new MinimalSignatureBackend(),
});
await resolver.setPublicKey(publicKeyPem);
```

依赖 `@noble/ed25519` + `@noble/hashes`（纯 JS，无平台 API 依赖——不使用 `crypto.subtle`/`atob`/`TextEncoder`/`new URL`/`Buffer`），适用于微信 / 支付宝 / 字节小程序。

> **小程序接入注意**：所有包为 ESM-only，需用打包工具（webpack / rollup / esbuild）转为 CommonJS。`TemplateEngine` 使用 `String.prototype.matchAll`（ES2020），旧版小程序运行时需 polyfill。`??` 运算符需 Babel 降级。`@noble/hashes` 为纯 JS 实现，需在微信开发者工具中实测确认运行无平台 API 依赖问题。

### 可选能力

```ts
// 密钥轮换：按 kid 注册多把公钥
await resolver.setPublicKey('key-2024', publicKeyPemV2);
await resolver.setPublicKey('key-2023', publicKeyPemV1);

// 惰性回调：未静态注册的变量名会走回调
resolver.setResolver((name) => {
  if (name === 'token') return fetchToken();
  return null;
});

// 可信 URL 收口：scheme 默认仅 https；host 白名单已在构造期决定，
// setAllowedHosts 用于运行期调整。两个 setter 均不接受 null；
// 关闭校验的唯一方式是显式通配 ['*']
resolver.setAllowedSchemes(['https']);
resolver.setAllowedHosts(['api.example.com']);

// 注意：[]（空数组）不是"关闭"而是"拒绝一切 host"（fail-closed）；
// 关闭校验的唯一方式是显式通配 ['*']，null 会抛错

```

失败以类型化错误抛出：`VerificationError` / `ResolutionError` / `TrustError`（均继承 `LinkSealError`，携带 `code` 字段）。宿主应分支于 `code` 而非消息文本，**也不要依赖 `error.name`**——压缩/混淆会改变子类的 constructor name，`code` 字段不受影响。

### 缺失变量策略

| `missing` | 行为 |
|---|---|
| `'error'` | 变量缺失则抛出 `MISSING_VARIABLE` |
| `'ignore'` | query 位的缺失参数被整个丢弃；简单替换位展开为空字符串（**路径段占位符禁止使用 `ignore`**，会产生退化 URL） |
| `'default'` | 用 `defaults` 中同名值填充 |

```ts
const payload: LinkSealProtocol = {
  version: '1.0',
  template: 'https://api.example.com/users/{userId}{?locale}',
  policy: { missing: 'default', defaults: { locale: 'zh-CN' } },
};
```

## 构建与测试

```bash
cd javascript && pnpm install      # 安装依赖
cd javascript && pnpm build        # 构建全部包
cd javascript && pnpm -r test     # 运行全部测试
```

单独测试某个包：

```bash
cd javascript && pnpm --filter unilink-seal-resolver test
cd javascript && pnpm --filter unilink-seal-crypto-minimal test
```

解析方两个验签后端（WebCrypto / minimal）的测试包含交叉一致性验证，确保对同一签名和篡改的判定完全一致。

## 与 Java SDK 的关系

两端共享同一份[协议规范](../spec/PROTOCOL.md)。跨语言字节级一致性由 `spec/examples/` 下的钉子示例保证——两端测试均读取这些示例，验证对同一 payload 产出完全相同的签名。
