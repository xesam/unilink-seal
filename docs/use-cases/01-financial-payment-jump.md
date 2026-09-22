# 场景 1：金融 App 支付跳转

## 1. 背景

金融 App 需要从服务端动态下发支付跳转模板，客户端验签后填充用户敏感信息（订单 ID、支付令牌），确保：
- 跳转目标来自可信后端（密码学保证模板未被篡改）
- 中间人无法注入钓鱼域名
- 最终 URL 的 host 在客户端白名单内（即使私钥泄露，host 白名单兜底）

**典型模板**：
```
https://pay.example.com/checkout/{orderId}?token={token}&timestamp={timestamp}
```

## 2. 威胁模型

### 2.1 中间人篡改模板
**攻击**：中间人拦截模板下发，修改 host 为 `https://phishing-pay.evil.com`

**防御**：Ed25519 签名验证失败 → 客户端拒绝展开

### 2.2 私钥泄露后的注入
**攻击**：攻击者获得签发方私钥，签发恶意模板指向钓鱼站

**防御**：客户端 `LinkSealCore` 构造期强制 host 白名单 → 即使签名合法，`phishing-pay.evil.com` 不在白名单，抛 `UNTRUSTED_URL` 错误

### 2.3 变量填充阶段的注入
**攻击**：恶意代码在客户端注入假 `token` 或篡改 `orderId`

**防御**：协议不负责变量来源的可信性——这属于客户端内部安全边界（如 Keychain 访问控制、代码混淆）

## 3. 代码示例

### 3.1 服务端签发（Node.js）

```typescript
import { ProtocolSigner } from 'unilink-seal-signer';
import type { LinkSealProtocol } from 'unilink-seal';

const signer = new ProtocolSigner();
await signer.setPrivateKey(process.env.ED25519_PRIVATE_KEY_PEM);

// 支付模板：客户端填充 orderId / token / timestamp
const payload: LinkSealProtocol = {
  version: '1.0',
  template: 'https://pay.example.com/checkout/{orderId}?token={token}&timestamp={timestamp}',
  policy: { 
    missing: 'error' // 任一变量缺失都拒绝跳转
  },
  expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 分钟有效期
};

const signed = await signer.signProtocol(payload);

// 下发给客户端（如通过订单详情接口）
res.json({ 
  paymentJumpProtocol: signed 
});
```

### 3.2 客户端验签 + 展开（TypeScript / React Native）

```typescript
import { LinkSealCore } from 'unilink-seal-resolver';
import type { SignedProtocol } from 'unilink-seal';

// 初始化 Resolver，强制 host 白名单（构造期校验）
const resolver = new LinkSealCore({ 
  allowedHosts: ['pay.example.com'] // 只信任支付域名
});
await resolver.setPublicKey(ED25519_PUBLIC_KEY_PEM); // 公钥从 App 内置或远程获取

// 从订单详情接口拿到签名模板
const signed: SignedProtocol = orderDetail.paymentJumpProtocol;

try {
  // 静态注册变量（从本地安全存储获取）
  resolver.setVariables({
    orderId: order.id,
    token: await getPaymentToken(), // 从 Keychain 获取
    timestamp: Date.now().toString(),
  });

  const finalUrl = await resolver.generateUrl(signed);
  // 成功：https://pay.example.com/checkout/ORDER123?token=SECRET&timestamp=1735000000

  // 导航到支付页（WebView / 外部浏览器 / universal link）
  navigateToPayment(finalUrl);

} catch (error) {
  if (error.code === 'INVALID_SIGNATURE') {
    // 签名验证失败 → 模板被篡改，拒绝跳转
    showError('支付链接不可信，请联系客服');
  } else if (error.code === 'PROTOCOL_EXPIRED') {
    // 模板已过期（超过 5 分钟）
    showError('支付链接已失效，请刷新订单');
  } else if (error.code === 'UNTRUSTED_URL') {
    // host 不在白名单（如私钥泄露后的恶意模板）
    showError('支付链接目标不可信');
  } else if (error.code === 'MISSING_VARIABLE') {
    // 客户端未提供 token（如 Keychain 读取失败）
    showError('支付令牌缺失，请重新登录');
  }
}
```

### 3.3 错误场景演示

#### 场景 A：中间人篡改 host
```typescript
// 攻击者修改模板为 https://phishing.evil.com/checkout/{orderId}
// 并重新伪造签名（但无法伪造 Ed25519 签名）

await resolver.generateUrl(tamperedSigned);
// 抛出：VerificationError { code: 'INVALID_SIGNATURE' }
```

#### 场景 B：私钥泄露，签发恶意模板
```typescript
// 攻击者获得私钥，签发合法签名的恶意模板
const maliciousPayload = {
  version: '1.0',
  template: 'https://phishing-pay.evil.com/steal?user={orderId}', // 钓鱼站
  policy: { missing: 'error' },
};
const maliciousSigned = await attackerSigner.signProtocol(maliciousPayload);

// 客户端收到后
await resolver.generateUrl(maliciousSigned);
// 抛出：TrustError { code: 'UNTRUSTED_URL', message: 'Host "phishing-pay.evil.com" not in allowlist' }
```

## 4. 安全边界

| 层面 | UniLink Seal 保证 | 不保证（宿主职责） |
|---|---|---|
| **模板完整性** | ✅ Ed25519 签名验证 | - |
| **模板来源可信** | ✅ 公钥来自可信通道 | 公钥分发机制（如内置 + 远程更新） |
| **最终 URL 可信** | ✅ host 白名单强制 | - |
| **变量来源可信** | ❌ | 客户端内部安全（Keychain、代码混淆） |
| **跳转执行安全** | ❌ | WebView 权限、Cookie 策略、用户确认 |
| **防重放** | ⚠️ `expiresAt` 限协议有效期 | 一次性消费语义（如宿主维护 nonce 集合） |

## 5. 为何不用 JWT

**JWT 方案**：后端直接签名完整 URL
```json
{
  "url": "https://pay.example.com/checkout/ORDER123?token=SECRET&timestamp=...",
  "exp": 1735000000
}
```

**问题**：
1. **后端需要知道 `token`**：支付令牌在客户端生成/刷新时，需额外上传给后端才能拼 URL
2. **时效性差**：URL 中的 `timestamp` 在签发时固定，客户端延迟跳转时可能已失效
3. **协议立场缺失**：JWT 是通用签名，「占位符是意图、缺失变量策略、host 白名单收口」需要自己设计

**UniLink Seal 优势**：
- 模板在后端签发，变量在客户端本地填充 → 后端无需知道敏感变量
- `timestamp` 在跳转时刻生成 → 时效性好
- 协议立场内置 → 少踩坑
