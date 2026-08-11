# PortSwigger Lab 做题进度

> 靶场：https://portswigger.net/web-security

---

## Access Control（访问控制/越权）— 已完成 13/13 ✅（2026-08-11 完结）

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

## Authentication（认证缺陷）— 已完成 4/14（2026-08-11 开始）

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | Username enumeration via different responses | 用户名枚举（响应差异） | 登录失败响应不同：账号不存在 vs 密码错误 → 逐个试用户名，看响应区别 |
| 2 | 2FA simple bypass | 2FA 流程绕过 | 登录后直接访问受保护页面，跳过 2FA 验证步骤 |
| 3 | Password reset broken logic | 密码重置逻辑缺陷 | 重置流程中修改 username 参数指向目标账号，token 未绑定原账号 |
| 4 | Username enumeration via subtly different responses | 用户名枚举（细微差异） | 响应几乎相同，但个别字符/长度/状态码有细微差别 → 对比响应体找差异 |

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

---

## 下一阶段

Access Control 已全部完成 ✅，Authentication 进行中（4/14），剩余：
- Username enumeration via response timing（响应时间差异枚举）
- Broken brute-force protection, IP block（IP 封锁绕过）
- Username enumeration via account lock（账户锁定枚举）
- 2FA broken logic / 2FA bypass using a brute-force attack（2FA 逻辑缺陷/爆破）
- Brute-forcing a stay-logged-in cookie（remember-me Cookie 爆破）
- Offline password cracking（离线密码破解）
- Password reset poisoning via middleware（中间件密码重置投毒）
- Password brute-force via password change（改密接口爆破）
- Broken brute-force protection, multiple credentials per request（单请求多凭据）

