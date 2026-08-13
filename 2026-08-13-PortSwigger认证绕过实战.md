# 2026-08-13 PortSwigger 认证机制绕过实战（Authentication 7/14 → 11/14）

> 状态：✅ 实操过（4 关全过，2026-08-13）

> 零碎 lab 笔记精简版：题目 / 要点 / 踩坑点。进度明细在 `PortSwigger-Lab-做题进度.md`。

## Lab 1: 2FA bypass using a broken logic（2FA 逻辑缺陷）

- **要点**：`verify` 参数决定"验证谁的码"且客户端可控 → GET /login2 改 `verify=carlos` 触发目标验证码 → 爆 `mfa-code`(0000-9999) → **302 命中**
- **踩坑**：Burp CE 版 Intruder 限速（~1 req/s），线程拉满没用 → 换 Python 60 并发，2 分钟跑完 10000 次；失败 200 / 成功 302，信号干净

## Lab 2: Brute-forcing a stay-logged-in cookie（remember-me 伪造）

- **要点**：`cookie = base64(用户名:md5(密码))` 结构公开可伪造 → 离线预生成 `base64(carlos:md5(候选词))` 列表导入 Intruder 爆破 → **200 命中即登录**
- **踩坑**：必须**删掉自己的 session cookie** 只留 stay-logged-in，否则服务端优先认 session，全部返回 200 攻击失效
- **补充**：官方用 Payload processing（Hash: MD5 → Add prefix → Base64）请求时动态转换，字典可复用；判定用业务特征（"Update email" 按钮）比状态码稳

## Lab 3: Offline password cracking（离线破解）

- **要点**：评论区存储型 XSS 偷 carlos 的 stay-logged-in cookie → 解码得 `carlos:md5` → 离线破解（hashcat -m 0 / 反查）→ 明文登录删账户
- **踩坑**：exploit server 这关是**收件箱**（XSS 主动送来，去日志翻）不是发起点；偷到的 cookie 本身就能登录（会话接管），破解出明文是"长期资产"

## Lab 4: Password reset poisoning via middleware（密码重置投毒）

- **要点**：token 本身安全，漏洞在**重置链接域名由 X-Forwarded-Host 拼接且未校验** → 加头指向 exploit server → carlos 点邮件链接 → `temp-forgot-password-token` 进 Access log → 换 token 改密登录
- **踩坑**：拿自己 wiener 的合法重置链接（指向 lab 域名的那个）换 token 参数，比手动拼 URL 稳

## 方法论沉淀（四关通用）

1. **先验证后攻击**：先用自己的凭据端到端跑通攻击链，再打目标
2. **业务特征判命中**（登录态专属元素 grep-match）比状态码可靠
3. **隔离凭据源**：测哪个凭据，请求里只带哪个（如只留 stay-logged-in）
4. 工具：ffuf 满并发替代 Burp CE；`seq -w 0 9999` 生成字典

## 待实践

- [ ] Authentication 剩余 3 关：2FA 爆破 / 改密接口爆破 / 单请求多凭据
- [ ] hashcat 规则变形（`-r`）、Turbo Intruder
- [ ] Spring Security RememberMe 源码：随机 token + 服务端存储的正确实现

## 关联笔记

- [登录脆弱与认证缺陷](./2026-08-09-登录脆弱与认证缺陷.md) / [Token 安全与防护绕过](./2026-08-10-Token安全与防护绕过.md) / [JWT 安全与攻击](./2026-08-12-JWT安全与攻击.md) / [找回与重置机制的逻辑越权](./2026-08-09-找回与重置机制的逻辑越权.md) / [XSS 跨站脚本攻击入门](./2026-08-02-XSS跨站脚本攻击入门.md)

> ⚠️ 声明：以上技术仅用于 CTF 竞赛和授权靶场环境。
