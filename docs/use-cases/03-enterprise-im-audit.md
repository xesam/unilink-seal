# 场景 3：企业 IM 安全跳转与审计

## 1. 背景

企业 IM（如企业微信、钉钉、飞书）需要支持跳转到第三方服务（OA 审批、文档系统、BI 报表），同时满足企业安全合规要求：

- **跳转目标可审计**：记录「谁在何时跳转到哪个服务」，供安全审计与事后追溯
- **模板来源可追溯**：签名保证模板来自可信 IM 服务器（而非第三方服务自己注入）
- **可信服务白名单**：强制 host 白名单，拒绝未授权的第三方服务
- **敏感变量本地填充**：用户身份令牌、会话 ID 等敏感信息在客户端本地填充，不经过 IM 服务器

**典型模板**：
```
https://oa.company.com/approval/{flowId}?userId={userId}&token={token}
https://docs.company.com/view/{docId}?viewer={userId}&session={sessionId}
```

## 2. 合规要求

### 2.1 等保 2.0 / ISO 27001 相关条款

- **身份鉴别（A8.1）**：用户跳转到第三方服务时，服务需验证用户身份
- **访问控制（A9.1）**：只有授权的第三方服务才能被跳转
- **安全审计（A12.4）**：记录跳转行为（时间、用户、目标 URL）

### 2.2 UniLink Seal 如何满足

| 要求 | 实现方式 |
|---|---|
| **模板来源可追溯** | Ed25519 签名 → 模板必须来自 IM 服务器（持有私钥） |
| **可信服务白名单** | `LinkSealCore` 构造期强制 host 白名单 |
| **审计日志** | 记录 `(userId, timestamp, template, finalUrl, signatureValid)` |
| **敏感变量隔离** | `token` / `sessionId` 在客户端本地填充，不上传给 IM 服务器 |

## 3. 代码示例

### 3.1 IM 服务端签发（Node.js）

```typescript
import { ProtocolSigner } from 'unilink-seal-signer';

const signer = new ProtocolSigner();
await signer.setPrivateKey(IM_SERVER_PRIVATE_KEY_PEM);

// OA 审批跳转模板（签发后存入数据库，关联到 OA 应用）
const oaApprovalTemplate: LinkSealProtocol = {
  version: '1.0',
  template: 'https://oa.company.com/approval/{flowId}?userId={userId}&token={token}',
  policy: { missing: 'error' }, // 任一变量缺失都拒绝跳转
  expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 年有效期
  kid: 'im-server-2024', // 密钥标识（便于密钥轮换）
};

const signed = await signer.signProtocol(oaApprovalTemplate);

// 存入数据库，关联到 OA 应用配置
await db.thirdPartyApps.update({
  appId: 'oa-system',
  jumpTemplate: signed,
  allowedHosts: ['oa.company.com'], // 该应用的 host 白名单
});
```

### 3.2 IM 客户端验签 + 审计（Electron / React）

```typescript
import { LinkSealCore } from 'unilink-seal-resolver';
import type { SignedProtocol } from 'unilink-seal';

// 全局 Resolver，启动时初始化
class SecureJumpManager {
  private resolvers = new Map<string, LinkSealCore>(); // 每个第三方应用一个 Resolver

  async initApp(appId: string, allowedHosts: string[]) {
    const resolver = new LinkSealCore({ allowedHosts });
    await resolver.setPublicKey(IM_SERVER_PUBLIC_KEY_PEM); // IM 服务器公钥
    this.resolvers.set(appId, resolver);
  }

  async jump(appId: string, template: SignedProtocol, variables: Record<string, string>) {
    const resolver = this.resolvers.get(appId);
    if (!resolver) throw new Error(`App ${appId} not initialized`);

    const userId = getCurrentUserId();
    const timestamp = Date.now();

    try {
      // 静态注册变量（从本地安全存储获取）
      resolver.setVariables(variables);

      const finalUrl = await resolver.generateUrl(template);

      // ✅ 记录审计日志（跳转成功）
      await this.logAudit({
        userId,
        timestamp,
        appId,
        template: template.payload.template,
        finalUrl,
        signatureValid: true,
        action: 'jump_success',
      });

      // 打开外部浏览器或 WebView
      window.open(finalUrl);

    } catch (error) {
      // ❌ 记录审计日志（跳转失败）
      await this.logAudit({
        userId,
        timestamp,
        appId,
        template: template.payload.template,
        finalUrl: null,
        signatureValid: error.code !== 'INVALID_SIGNATURE',
        action: 'jump_failed',
        errorCode: error.code,
        errorMessage: error.message,
      });

      // 向用户展示错误
      if (error.code === 'INVALID_SIGNATURE') {
        showError('跳转链接不可信，已拒绝并记录审计日志');
      } else if (error.code === 'UNTRUSTED_URL') {
        showError('目标服务未授权，已拒绝并记录审计日志');
      } else if (error.code === 'PROTOCOL_EXPIRED') {
        showError('跳转模板已过期，请联系管理员更新');
      }
    }
  }

  private async logAudit(log: AuditLog) {
    // 发送到审计日志服务（不可篡改的日志存储）
    await fetch('/api/audit/jump', {
      method: 'POST',
      body: JSON.stringify(log),
    });

    // 可选：发送到本地日志文件（供离线审计）
    fs.appendFileSync('/var/log/im-jump-audit.log', JSON.stringify(log) + '\n');
  }
}

// 初始化第三方应用（启动时从服务端拉取配置）
const jumpManager = new SecureJumpManager();
await jumpManager.initApp('oa-system', ['oa.company.com']);
await jumpManager.initApp('doc-system', ['docs.company.com']);

// 用户点击「跳转到 OA 审批」按钮
async function onJumpToOA(flowId: string) {
  const template = await fetchTemplate('oa-system'); // 从服务端拉取签名模板

  await jumpManager.jump('oa-system', template, {
    flowId,
    userId: getCurrentUserId(),
    token: await getAuthToken(), // 从本地 Keychain 获取 OA 令牌
  });
}
```

### 3.3 审计日志查询（管理员后台）

```typescript
// 查询某用户的跳转记录
GET /api/audit/jump?userId=USER123&startTime=2024-01-01&endTime=2024-12-31

// 响应
[
  {
    "userId": "USER123",
    "timestamp": 1704067200000,
    "appId": "oa-system",
    "template": "https://oa.company.com/approval/{flowId}?userId={userId}&token={token}",
    "finalUrl": "https://oa.company.com/approval/FLOW456?userId=USER123&token=***",
    "signatureValid": true,
    "action": "jump_success"
  },
  {
    "userId": "USER123",
    "timestamp": 1704070800000,
    "appId": "unknown-service",
    "template": "https://malicious.site/steal?user={userId}",
    "finalUrl": null,
    "signatureValid": false,
    "action": "jump_failed",
    "errorCode": "INVALID_SIGNATURE"
  }
]
```

## 4. 安全事件响应

### 4.1 场景 A：检测到恶意模板注入

**事件**：审计日志显示多个用户收到签名无效的模板

```json
{
  "errorCode": "INVALID_SIGNATURE",
  "template": "https://phishing.site/steal?user={userId}",
  "count": 127,
  "affectedUsers": ["USER123", "USER456", ...]
}
```

**响应**：
1. 自动阻断：客户端已拒绝跳转（签名验证失败）
2. 溯源：查询模板来源（可能是第三方 SDK 注入、中间人攻击）
3. 通知：向受影响用户推送安全警告

### 4.2 场景 B：私钥泄露

**事件**：IM 服务器私钥泄露，攻击者可签发任意合法模板

**响应**：
1. **立即轮换密钥**：
   ```typescript
   // 生成新密钥对，kid 改为 im-server-2025
   const newSigner = new ProtocolSigner();
   await newSigner.setPrivateKey(NEW_PRIVATE_KEY_PEM);
   
   // 重新签发所有模板（kid = 'im-server-2025'）
   const newTemplate = await newSigner.signProtocol({
     ...oldPayload,
     kid: 'im-server-2025',
   });
   ```

2. **客户端注册新公钥**：
   ```typescript
   // 支持多把公钥（旧签名仍可验证，但逐步淘汰）
   resolver.setPublicKey('im-server-2024', OLD_PUBLIC_KEY_PEM);
   resolver.setPublicKey('im-server-2025', NEW_PUBLIC_KEY_PEM);
   ```

3. **host 白名单兜底**：即使签名合法，恶意 host 仍被 `UNTRUSTED_URL` 拒绝

## 5. 合规审计报告生成

### 5.1 月度审计报告

```typescript
// 生成月度跳转统计
async function generateMonthlyReport(year: number, month: number) {
  const logs = await db.auditLogs.find({
    timestamp: { $gte: startOfMonth, $lt: endOfMonth }
  });

  return {
    总跳转次数: logs.length,
    成功跳转: logs.filter(l => l.action === 'jump_success').length,
    失败跳转: logs.filter(l => l.action === 'jump_failed').length,
    签名无效次数: logs.filter(l => l.errorCode === 'INVALID_SIGNATURE').length,
    未授权服务: logs.filter(l => l.errorCode === 'UNTRUSTED_URL').length,
    过期模板: logs.filter(l => l.errorCode === 'PROTOCOL_EXPIRED').length,
    
    // 按应用分组
    应用跳转分布: groupBy(logs, 'appId'),
    
    // 高频用户（top 10）
    高频用户: topUsers(logs, 10),
    
    // 异常事件（签名无效 + 未授权服务）
    异常事件: logs.filter(l => 
      l.errorCode === 'INVALID_SIGNATURE' || 
      l.errorCode === 'UNTRUSTED_URL'
    ),
  };
}
```

### 5.2 实时告警

```typescript
// 检测异常模式（5 分钟内同一用户 3 次签名无效）
const recentFailures = await db.auditLogs.find({
  userId: 'USER123',
  errorCode: 'INVALID_SIGNATURE',
  timestamp: { $gte: Date.now() - 5 * 60 * 1000 }
});

if (recentFailures.length >= 3) {
  // 触发告警：可能的中间人攻击或模板污染
  await alertSecurityTeam({
    level: 'high',
    message: `用户 ${userId} 在 5 分钟内遇到 3 次签名无效，疑似中间人攻击`,
    evidence: recentFailures,
  });

  // 可选：自动锁定该用户的跳转能力（需人工审核解锁）
  await db.users.update({ userId }, { jumpDisabled: true });
}
```

## 6. 与传统方案对比

### 6.1 方案 A：直接跳转（无签名）

```typescript
// IM 服务器返回完整 URL
const url = `https://oa.company.com/approval/${flowId}?userId=${userId}&token=${token}`;
window.open(url);
```

**问题**：
- 无法审计模板来源（URL 可被第三方 SDK 任意构造）
- 无法防止钓鱼（恶意 SDK 注入 `https://fake-oa.site`）
- 敏感变量（`token`）必须经过 IM 服务器（隐私风险）

### 6.2 方案 B：OAuth 重定向

```typescript
// 用户点击跳转 → IM 服务器生成 OAuth code → 跳转到第三方服务
const authCode = await generateOAuthCode(userId);
const url = `https://oa.company.com/oauth/callback?code=${authCode}`;
window.open(url);
```

**问题**：
- OAuth 流程复杂（需要第三方服务接入 IM 的 OAuth）
- 仍无法审计最终跳转的具体页面（只知道跳转到 `oa.company.com`，不知道具体 `flowId`）

### 6.3 方案 C：UniLink Seal

**优势**：
- ✅ 模板签名 → 可审计来源
- ✅ host 白名单 → 防钓鱼
- ✅ 本地变量填充 → 隐私保护
- ✅ 完整审计日志 → 记录 `(userId, template, finalUrl, timestamp)`

**劣势**：
- 需要集成 SDK（相比直接 `window.open` 有开发成本）
- 密钥管理负担（需要定期轮换、多环境隔离）

## 7. 最佳实践

### 7.1 密钥隔离

- **生产环境**：独立密钥对（`im-prod-2024`）
- **测试环境**：独立密钥对（`im-test-2024`）
- **定期轮换**：每 6 个月轮换一次（新旧公钥并存 1 个月过渡期）

### 7.2 审计日志存储

- **实时日志**：写入 Elasticsearch / ClickHouse（供实时告警）
- **归档日志**：写入对象存储（S3 / OSS），保留 7 年（满足等保要求）
- **日志签名**：审计日志本身也可用 HMAC 签名（防篡改）

### 7.3 用户体验优化

- **预加载模板**：启动时批量拉取常用模板，减少跳转延迟
- **错误提示友好**：`INVALID_SIGNATURE` → "跳转链接不可信"（而非直接展示错误码）
- **离线兜底**：模板缓存 + 离线可用（网络故障时仍可跳转）
