# 场景 2：小程序 / 小游戏本地跳转

## 1. 背景

微信小程序、抖音小程序等环境需要从服务端获取跳转模板（指向原生页面或其他小程序），本地验签后填充用户相关变量，生成 deeplink / schema URL 后交给宿主跳转。

**典型模板**：
```
myapp://profile/{userId}?tab={tab}&from={source}
weixin://dl/business/?appid={appid}&path=pages/detail&query=id%3D{itemId}
```

**核心需求**：
- 模板可缓存在小程序本地（减少网络请求）
- 变量由小程序本地持有（如用户 ID 从本地缓存读取，无需每次向服务端请求）
- 服务端无需知道这些变量的值（隐私保护）
- 签名保证模板来自可信后端（防止注入恶意跳转）

## 2. 为何不直接下发完整 URL

### 2.1 方案对比

**方案 A：服务端返回完整 URL**
```json
{
  "jumpUrl": "myapp://profile/USER123?tab=orders&from=banner"
}
```

**问题**：
- 服务端需要知道 `userId`（小程序需上传给后端）
- 每次跳转都需要网络请求（无法离线跳转）
- `from` 参数在不同入口（banner / 列表 / 搜索）需要多个接口或动态参数

**方案 B：UniLink Seal 签名模板**
```json
{
  "signedProtocol": {
    "payload": {
      "version": "1.0",
      "template": "myapp://profile/{userId}?tab={tab}&from={source}",
      "policy": { "missing": "error" }
    },
    "signature": "..."
  }
}
```

**优势**：
- 模板可缓存，离线跳转
- `userId` / `tab` / `source` 在小程序本地填充（无需上传给后端）
- 一个模板支持多入口（`source` 由点击位置决定）

## 3. 代码示例

### 3.1 服务端签发（Node.js）

```typescript
import { ProtocolSigner } from 'unilink-seal-signer';

const signer = new ProtocolSigner();
await signer.setPrivateKey(ED25519_PRIVATE_KEY_PEM);

// 用户详情页跳转模板
const profileJumpTemplate: LinkSealProtocol = {
  version: '1.0',
  template: 'myapp://profile/{userId}?tab={tab}&from={source}',
  policy: { 
    missing: 'default', 
    defaults: { 
      tab: 'home',    // 默认 tab
      source: 'app'   // 默认来源
    }
  },
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 天有效期
};

const signed = await signer.signProtocol(profileJumpTemplate);

// 下发给小程序（可通过配置接口批量下发多个模板）
res.json({
  templates: {
    profileJump: signed,
    // 其他模板...
  }
});
```

### 3.2 小程序端验签 + 展开（TypeScript / Taro）

```typescript
import { LinkSealCore } from 'unilink-seal-resolver';
import Taro from '@tarojs/taro';

// 初始化 Resolver（全局单例，启动时初始化）
const resolver = new LinkSealCore({ 
  // 小程序通常只跳自己的 schema 或微信 universal link，host 白名单按需配置
  allowedHosts: ['*'] // 或具体域名白名单
});
await resolver.setPublicKey(PUBLIC_KEY_PEM); // 公钥从小程序内置或远程获取

// 从本地缓存读取模板（启动时从服务端拉取并缓存）
const cachedTemplates = Taro.getStorageSync('jump_templates');
const profileTemplate = cachedTemplates.profileJump;

// 用户点击「查看我的订单」按钮
function onViewMyOrders() {
  try {
    // 静态注册变量（从本地存储获取）
    resolver.setVariables({
      userId: Taro.getStorageSync('userId'),  // 本地缓存的用户 ID
      tab: 'orders',                          // 跳转到订单 tab
      source: 'home_button',                  // 来源：首页按钮
    });

    const deeplink = await resolver.generateUrl(profileTemplate);
    // 生成：myapp://profile/USER123?tab=orders&from=home_button

    // 执行跳转（微信小程序用 navigateTo / redirectTo，原生 schema 用 universal link）
    if (deeplink.startsWith('myapp://')) {
      // 调用原生能力跳转
      wx.navigateToMiniProgram({ ... });
    } else {
      Taro.navigateTo({ url: `/pages/profile?tab=orders&from=home_button` });
    }

  } catch (error) {
    if (error.code === 'INVALID_SIGNATURE') {
      // 模板被篡改，拒绝跳转
      Taro.showToast({ title: '跳转链接不可信', icon: 'none' });
    } else if (error.code === 'PROTOCOL_EXPIRED') {
      // 模板过期（超过 30 天），提示用户升级小程序
      Taro.showModal({
        title: '版本过旧',
        content: '请升级到最新版本',
        success: () => {
          // 清除缓存，下次启动重新拉取模板
          Taro.removeStorageSync('jump_templates');
        }
      });
    } else if (error.code === 'MISSING_VARIABLE') {
      // userId 缺失（用户未登录）
      Taro.navigateTo({ url: '/pages/login' });
    }
  }
}
```

### 3.3 不同入口复用同一模板

```typescript
// 场景 A：从首页 banner 跳转
resolver.clearVariables(); // 清空之前的变量
resolver.setVariables({
  userId: currentUserId,
  tab: 'profile',
  source: 'home_banner', // 来源：首页 banner
});
const url1 = await resolver.generateUrl(profileTemplate);
// myapp://profile/USER123?tab=profile&from=home_banner

// 场景 B：从搜索结果跳转
resolver.clearVariables();
resolver.setVariables({
  userId: currentUserId,
  tab: 'posts',
  source: 'search_result', // 来源：搜索结果
});
const url2 = await resolver.generateUrl(profileTemplate);
// myapp://profile/USER123?tab=posts&from=search_result
```

## 4. 微信小程序特殊处理

### 4.1 跳转其他小程序

微信小程序跳转其他小程序时，URL 需遵循 `weixin://dl/business/?appid=...&path=...&query=...` 格式：

```typescript
// 服务端签发跳转到电商小程序的模板
const wechatMiniAppTemplate: LinkSealProtocol = {
  version: '1.0',
  // query 需 URL 编码（id%3D 是 id= 的编码）
  template: 'weixin://dl/business/?appid={targetAppId}&path=pages/detail&query=id%3D{itemId}',
  policy: { missing: 'error' },
};

// 小程序端展开
resolver.setVariables({
  targetAppId: 'wx1234567890abcdef', // 目标小程序 appId
  itemId: 'ITEM789',                  // 商品 ID
});
const url = await resolver.generateUrl(wechatMiniAppTemplate);
// weixin://dl/business/?appid=wx1234567890abcdef&path=pages/detail&query=id%3DITEM789

// 调用微信 API 跳转
wx.navigateToMiniProgram({
  appId: 'wx1234567890abcdef',
  path: 'pages/detail?id=ITEM789', // 从 deeplink 解析出 path 与 query
  success: () => console.log('跳转成功'),
});
```

### 4.2 使用惰性回调动态生成参数

某些参数需要在跳转时刻生成（如时间戳、会话 ID），可用惰性回调：

```typescript
// 注册惰性回调（优先级低于静态注册）
resolver.setResolver((name) => {
  if (name === 'timestamp') {
    return Date.now().toString(); // 跳转时刻生成时间戳
  }
  if (name === 'sessionId') {
    return Taro.getStorageSync('current_session_id');
  }
  return null; // 未识别的占位符返回 null
});

// 静态注册优先：userId 静态注册，timestamp 由回调生成
resolver.setVariables({ userId: currentUserId });

const url = await resolver.generateUrl(profileTemplate);
// 每次调用 generateUrl 时，timestamp 都是当前时刻
```

## 5. 安全边界

| 层面 | UniLink Seal 保证 | 不保证（宿主职责） |
|---|---|---|
| **模板完整性** | ✅ Ed25519 签名验证 | - |
| **模板来源可信** | ✅ 公钥来自可信通道 | 公钥分发机制（内置 + 远程更新） |
| **最终 URL 可信** | ✅ scheme 白名单（默认 `https`） | 自定义 scheme 需手动配置 |
| **变量来源可信** | ❌ | 小程序内部安全（本地存储加密） |
| **跳转执行安全** | ❌ | 微信 API 权限、用户确认弹窗 |

## 6. 性能优化

### 6.1 模板批量下发 + 本地缓存

```typescript
// 启动时一次性拉取所有模板
async function initTemplates() {
  const res = await fetch('/api/templates');
  const templates = await res.json();
  
  // 缓存到本地存储
  Taro.setStorageSync('jump_templates', templates);
  Taro.setStorageSync('templates_updated_at', Date.now());
}

// 每次启动检查是否过期（如超过 7 天）
if (Date.now() - Taro.getStorageSync('templates_updated_at') > 7 * 24 * 60 * 60 * 1000) {
  await initTemplates();
}
```

### 6.2 Resolver 实例复用

```typescript
// 全局单例，避免每次跳转都重新初始化
class JumpManager {
  private static resolver: LinkSealCore;

  static async init() {
    this.resolver = new LinkSealCore({ allowedHosts: ['*'] });
    await this.resolver.setPublicKey(PUBLIC_KEY_PEM);
  }

  static async jump(templateKey: string, variables: Record<string, string>) {
    const templates = Taro.getStorageSync('jump_templates');
    const template = templates[templateKey];
    
    this.resolver.clearVariables();
    this.resolver.setVariables(variables);
    
    const url = await this.resolver.generateUrl(template);
    // 执行跳转...
  }
}

// 小程序启动时初始化
await JumpManager.init();

// 业务代码中直接调用
await JumpManager.jump('profileJump', { userId: 'USER123', tab: 'orders' });
```

## 7. 与动态链接平台的对比

| 维度 | UniLink Seal | Branch.io / Firebase Dynamic Links |
|---|---|---|
| **签名保证** | ✅ 密码学保证模板未被篡改 | ❌ 依赖平台 HTTPS |
| **离线跳转** | ✅ 模板缓存本地，离线可用 | ❌ 需要网络请求短链解析 |
| **归因 / 路由** | ❌ 无 | ✅ 核心功能 |
| **成本** | 免费（MIT） | Branch 按 MAU 收费 |
| **适用场景** | App 内跳转、小程序跳转 | 跨 App 跳转、App 下载归因 |

**结论**：UniLink Seal 适合「小程序 / App 内跳转 + 本地变量填充 + 离线可用」场景；Branch.io 适合「跨 App 跳转 + 归因」场景。
