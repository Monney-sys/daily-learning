# 2026-09-12 PortSwigger XSS 模块实战（前七题）

> 状态：✅ 实操过（7 道全部通关）｜🧪 部分题目只在自己浏览器里验证过 payload，**投递到受害者**那一环还要再练熟
> 关联笔记：[XSS 入门认知框架](./2026-08-02-XSS跨站脚本攻击入门.md) · [XSS 平台工具与 HttpOnly 绕过](./2026-08-03-XSS平台工具与HttpOnly绕过.md) · [XSS WAF 绕过与安全修复](./2026-08-04-XSS-WAF绕过与安全修复.md)
> 进度跟踪：[PortSwigger-Lab-做题进度.md](./PortSwigger-Lab-做题进度.md)

## 一、这一轮做完的 7 道题（XSS 模块，全部 APPRENTICE）

| # | Lab | 我的输入落在哪（上下文） | 一句话打法 | 命中信号 |
|---|-----|------------------------|-----------|---------|
| 1 | Reflected XSS into HTML context with nothing encoded | HTML 文本 | 搜索词原样回显 → 直接插标签 | 弹窗 |
| 2 | Stored XSS into HTML context with nothing encoded | HTML 文本（存库） | 评论里插标签，存库后谁看谁中 | 弹窗 |
| 3 | DOM XSS in document.write sink using source location.search | **img 的 src 属性**（document.write 拼出来的） | 先闭合属性再插标签：`"><svg onload=…>` | 弹窗 |
| 4 | DOM XSS in innerHTML sink using source location.search | innerHTML（等于 HTML 文本） | `<script>` 走 innerHTML **不执行** → 用 `<img src=1 onerror=…>` | img 加载失败触发 |
| 5 | DOM XSS in jQuery anchor href attribute sink using location.search source | `<a href>`（jQuery 写进去的） | 不需要标签：`javascript:…` → 点 back 触发 | 点击后执行 |
| 6 | DOM XSS in jQuery selector sink using a hashchange event | `location.hash` → jQuery `$()` 选择器 | exploit server 放 iframe，`onload` 把 payload 追加到 hash 上 | 受害者浏览器弹窗 |
| 7 | Reflected XSS into attribute with angle brackets HTML-encoded | 带引号的属性值 | 尖括号被编码也不用怕：闭合引号 + 加事件属性 | 属性对应事件触发 |

> 说明：1-5 题的机制我按官方页面核对过（下面每题的「坑」是这类题真正的坑）；**6、7 两道是这次真正卡住我、也真正吃透的重点**，单独展开在第三节。

## 二、逐题记录

### Lab 1｜Reflected XSS into HTML context with nothing encoded

- **思路**：什么都不编码 → 输入就是 HTML 的一部分 → 插标签即可。
- **过程**：搜索框提交 payload，页面把搜索词原样吐回来，标签立刻被浏览器当元素解析。
- **怎么识别命中**：payload 一提交就弹窗（反射型不需要存库、不需要别人看）。
- **坑**：反射型必须**让别人访问带 payload 的 URL** 才算完成攻击 —— 用 exploit server 放 `<script>location='https://LAB/?search=payload'</script>` 再 Deliver 给受害者。
- **结果**：✅ 通关。

### Lab 2｜Stored XSS into HTML context with nothing encoded

- **思路**：评论内容会存库并在页面渲染 → 插标签，存一次、以后所有访问者都中。
- **过程**：在评论表单（评论/姓名/邮箱/网站 字段）里提交 payload，再打开帖子页面确认被执行。
- **怎么识别命中**：提交后刷新/别人访问帖子时弹窗 —— **不依赖那一次请求**，这是和反射型的最大区别。
- **坑**：存储型的价值在"一次注入、多次触发"（受害者浏览帖子即中），投递时用 exploit server 让受害者去看那条评论。
- **结果**：✅ 通关。

### Lab 3｜DOM XSS in document.write sink using source location.search

- **思路**：页面用 `document.write` 把搜索词拼进一个 `<img src="…">` → **我的输入落在属性里**，所以要先把属性闭合、再插自己的标签。
- **过程**：先搜一个随机字符串 →右键检查元素，看到它变成 `<img src="/resources/images/tracker.gif?searchTerms=我的字符串">` → 改成 `"><svg onload=print()>`。
- **怎么识别命中**：`<svg onload>` 不需要任何交互，插入即执行。
- **坑**：第一反应会直接在搜索框里写 `<script>…</script>` —— 因为已经在**属性值里面**，`<` 只是属性内容，永远闭合不了引号，写多少都不会执行。**先看上下文，再决定用什么 payload**。
- **结果**：✅ 通关。

### Lab 4｜DOM XSS in innerHTML sink using source location.search

- **思路**：搜索词被写进 `element.innerHTML` → 同样是 HTML 文本上下文，但**这里 `<script>` 不会执行**。
- **过程**：搜索框提交 `<img src=1 onerror=print()>` → 点击 Search。
- **怎么识别命中**：`src=1` 是无效地址 → 加载失败 → 触发 `onerror`。
- **坑**：**`innerHTML` 不执行 `<script>`**（浏览器规范如此，jQuery 也会剥掉）→ 必须换"会自己报错的元素 + 事件属性"。这条规则解释了我以前很多"payload 明明对但不弹"的情况。
- **结果**：✅ 通关。

### Lab 5｜DOM XSS in jQuery anchor href attribute sink using location.search source

- **思路**：页面用 jQuery 把 URL 参数（`returnPath`）写进 `<a href>` → **URL 属性不需要尖括号**，直接塞伪协议。
- **过程**：Submit feedback 页把 `returnPath` 改成随机串 → 右键检查元素，看到字符串落在 `a href` 里 → 改成 `javascript:print()` → 回车后点 "back"。
- **怎么识别命中**：**点击**那个链接时执行（不是加载时）。
- **坑**：这是"需要一次交互"的题型 —— 别指望页面加载就弹；另外 `javascript:` 伪协议是**在当前文档的 origin 里执行**，这也是"评论区放恶意网址跳转"和真正 XSS 的区别。
- **结果**：✅ 通关。

### Lab 6｜DOM XSS in jQuery selector sink using a hashchange event

- **思路**：首页有一段 jQuery 代码，用 `location.hash` 去自动滚动到某篇文章 → hash 被拼进 jQuery 选择器 → 老 jQuery 会把它当 HTML 造元素。
- **过程**：exploit server 的 **Body** 里放：
  ```html
  <iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
  ```
  → Store → View exploit 自测 → **Deliver to victim** 过关。
- **怎么识别命中**：自己浏览器里 `location.hash='<img src=x onerror=print()>'` 就能弹。
- **坑（这次卡最久）**：见第三节。
- **结果**：✅ 通关。

### Lab 7｜Reflected XSS into attribute with angle brackets HTML-encoded

- **思路**：`<>` 被 HTML 实体编码，但**引号没编码** → 闭合属性、再加一个事件处理器属性 —— 全程不需要尖括号。
- **过程**：搜索框提交随机串 → Burp 里看响应，发现落在 `value="…"` 里 → payload 用 `"autofocus onfocus="print()` 这类形态（官方形态是 `"onmouseover="alert(1)`）。
- **怎么识别命中**：自己浏览器里 Copy URL 打开 → 事件触发弹窗。
- **坑**：见第三节第三条。
- **结果**：✅ 通关。

## 三、这轮真正学到的东西（第三节 = 本篇重点）

### 1. 三类 sink ↔ 三种投递壳（这是最重要的认知）

| 类型 | payload 从哪进 | 谁执行 / 什么时刻 | 投递壳 |
|------|--------------|-----------------|--------|
| 反射型 | URL 参数，服务端回显进 HTML | 受害者打开含 payload 的 URL | `<script>location='https://LAB/?q=<img src=x onerror=print()>'</script>` |
| 存储型 | 表单字段 → 存库 → 页面输出 | 受害者访问页面时渲染（有的题要**点击**） | 提交评论（部分题不用 Deliver，有的就是自己点） |
| **纯 DOM 型** | 只存在浏览器里：`location.hash` / `location.search` | 受害者加载目标页 + **触发事件**时 | `iframe + onload` 改 hash |

**拿到新题先问三句**：payload 从哪进？服务端能不能看到它？谁在什么时候执行它？—— 答案决定用哪种壳。

> 我原来只有"评论区存链接 → 诱导人点击"一种思路（那是**存储型 + 交互**的路线），碰到 DOM 型就完全打不通：URL 片段**根本不会发给服务器**，评论区再怎么写也进不了 jQuery 选择器。

### 2. iframe + onload 的真实分工（实测）

```
iframe  = 把受害者的浏览器「带到目标站」（它有自己的 window/document，origin 是目标站的）
onload  = 到了之后「替受害者改一下地址」（this.src += payload → 制造一次 hash 变化）
payload = 目标站自己的那段 JS「读到这个地址后」执行的东西
```

- `onload` 里的代码跑在**我的 origin**（它属于我页面里的 iframe 元素），**不是**目标站 → 所以 onload 不是"放 payload"，是"安排一个动作"。
- **fragment 变化 = 同一文档内导航**：实测子文档加载计数仍为 1、文档内变量保留、服务器日志没有第二次请求，只触发 `hashchange`。
- 所以 **payload 不能直接写在 `src="…/#<img…>"` 里** —— 加载时就带着 hash，没有"变化"，`hashchange` 永远不触发。
- 优势对比：`window.open()` 会被浏览器当弹窗拦掉，**iframe 不会被拦** —— 这才是它能当"零交互投递"载体的原因。

### 3. 尖括号被 HTML 实体编码 ≠ 打不了

- 属性上下文里**不需要尖括号**：闭合引号 + 加一个事件处理器属性 = 在**页面本来就有的标签**上挂一个"会自动响的铃铛"。
- 官方 payload 结尾**不写引号**：`"onmouseover="alert(1)` —— 那个起始引号由页面原本的属性闭合引号**借来收尾**，能借就借（多写一个 `"` 遇到严格解析更容易翻车）。
- **哪个属性会执行，取决于"那个事件在注入的标签上会不会被触发"**（实测 7 种注入）：

| 注入的属性 | 页面加载后自动执行？ |
|-----------|-------------------|
| `autofocus` + `onfocus=` | ✅ **自动**（零交互，首选） |
| `style="animation:…"` + `onanimationstart=` | ✅ **自动**（需页面有对应 keyframes） |
| `onmouseover=` | ❌ 要鼠标划过 |
| `onfocus=`（无 autofocus） | ❌ 要手动聚焦 |
| `accesskey` + `onclick=` | ❌ 要按组合键 |
| `onload=`（挂在 input 上） | ❌ 这个标签根本不触发 load 事件 |
| 不闭合引号 | ❌ 整个 payload 都被当成属性值内容 |

- 官方 Hint 的原话值得记住：**"你能弹 ≠ 受害者能弹"** → 受害者机器人不一定动鼠标，所以要多试几个属性（这就是后面 Practitioner 题 "event handlers and href attributes blocked" 的核心：**穷举属性 = 解法**，不是运气）。

### 4. 编码/解码链（DOM 型的隐藏坑）

- 实测：浏览器会把片段里的 `<` `>` 空格做**百分号编码**，目标站收到的是 `#%3Cimg%20src=x%20onerror=print()%3E` → 所以目标端必须有 **`decodeURIComponent`** 才能还原成 HTML。
- 实战含义：**payload 里的特殊字符（`< > & # ?`）会不会被编码、目标端有没有解码，是这类题成败的关键**，不能想当然。

### 5. jQuery 选择器 sink 的版本边界（本地实测 10 个版本）

| jQuery | `$(location.hash)`（带 `#`） | 拼进 `:contains(<img …>)` |
|--------|---------------------------|--------------------------|
| ≤ 1.8.3 | 抛 `Syntax error` | **造出 `<img>` → onerror 触发 ✅** |
| ≥ 1.9.1（1.9/1.10/1.11/1.12/2.2/3.4/3.7） | 抛错 | ❌ 不造元素 |
| 任意版本 `$('<img …>')`（字符串以 `<` 开头） | — | ✅ |

- 结论：**可打边界 = 字符串以 `<` 开头进 `$()`（任何版本）**；带 `#` 前缀的形态在所有测试版本都抛错。
- 实战用法：看到"hash 拼进 jQuery 选择器"→ 先 `F12 → jQuery.fn.jquery` **查版本**，≤1.8.3 才是能打的。

### 6. 同源策略边界（跨域实测）

```
f.contentDocument         → null（拿不到）
f.contentWindow.location  → SecurityError
f.src += '…'              → ✅ 允许
```

我能做的**只有改它的地址**，改不了目标文档的 DOM —— 攻击链全程跑在受害者浏览器里，服务端日志什么都看不到（**这就是 DOM 型 XSS 难排查的原因**）。

## 四、方法论沉淀（以后拿到任意 XSS 题按这个走）

1. **找注入点**：每个可控参数都提交一个随机串（`test123xyz`），在响应/DevTools 里搜它
2. **判上下文**：它落在 HTML 文本 / 属性值（有引号？）/ JS 字符串 / URL 属性 / jQuery 选择器里
3. **测编码**：提交 `<>"'&()` 看哪些被编码 —— **只有被编码的字符才是障碍**，没编码的直接用
4. **定"时刻"**：这个 sink 什么时候执行？加载时 / 事件时（哪个事件）/ 点击时 —— 决定投递壳和属性选择
5. **选壳投递**：反射/存储 → script+location 或直接提交；DOM → iframe+onload
6. **投递后别急着以为失败**：受害者机器人触发的事件和你自己不一样（多试几个属性/换成零交互的）

**一句话**：XSS 题不是"背 payload"，是**"判上下文 → 判编码 → 判触发时刻 → 选壳"**四步。

## 五、待实践

- [ ] 用 exploit server 把 Lab 3/4/5 的**受害者投递**重打一遍（这三道我当时只在自己浏览器验证过）
- [ ] XSS 模块第 8 道：Stored XSS into anchor href attribute with double quotes HTML-encoded（正好是我原来"评论区放网址"思路的完整版，payload 用 `javascript:`）
- [ ] DOM 型继续：document.write sink inside a select element / AngularJS 表达式 / Reflected DOM XSS / Stored DOM XSS
- [ ] 把"零交互属性"这套（`autofocus onfocus` / `animation`）在后面的 bypass 题里验证一遍

## 六、疑问（同步登记在 OPEN-QUESTIONS.md）

- ❓ Lab 6 的真实 sink 拼接行是哪种形态（`:contains()` 还是别的）？我实测只有 ≤1.8.3 的 `:contains()` 形态能打，想去 DevTools 里把它那行代码抄下来对照。
- ❓ 受害者机器人到底会触发哪些事件？（官方说"多试几个属性"，那说明它触发的事件集合是有限的，值得记录一份白名单）

## 关联笔记

- [XSS 入门认知框架](./2026-08-02-XSS跨站脚本攻击入门.md) — 反射/存储/DOM 三型的原理底子
- [XSS 平台工具与 HttpOnly 绕过](./2026-08-03-XSS平台工具与HttpOnly绕过.md) — XSS Labs 1~13 实战
- [XSS WAF 绕过与安全修复](./2026-08-04-XSS-WAF绕过与安全修复.md) — 编码/混淆绕过手法
- [PortSwigger-Lab-做题进度.md](./PortSwigger-Lab-做题进度.md) — 模块进度

> ⚠️ 声明：以上全部在 PortSwigger Web Security Academy 授权靶场内完成；仅用于学习，请勿对未授权目标测试。
