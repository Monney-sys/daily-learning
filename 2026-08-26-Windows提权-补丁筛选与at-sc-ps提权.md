# 2026-08-26 权限提升②：Windows 提权（溢出漏洞 + at/sc/ps 命令提权 + 补丁筛选）

> 状态：🧪 理论（课程案例 1-3 + 思路点），待实操
> 小迪安全《提权》Windows 部分。承接昨天「提权概述」的 ③ 服务器系统(OS)分支，落到 Windows 具体打法：先**补丁筛选**判断能打哪个溢出洞，再用 **at / sc / ps** 这些命令类提权方法拿 system。补丁筛选工具已装 WES-NG 到 SecurityTools。

## 一、一句话认知

Windows 提权 = **信息收集 → 补丁筛选（找出缺的补丁 → 对应能打的 CVE/EXP）→ 用 MSF 或特定 EXP 拿 system**；除此之外还有 **at / sc / ps** 这类命令类提权，以及数据库提权、第三方提权。**不同环境/系统版本，方法适用面不一样**（案例1 的完整流程：信息收集 → 补丁筛选 → 利用 MSF 或特定 EXP → 执行 → 拿到权限）。

## 二、补丁筛选（找溢出漏洞的核心）

- **三个工具（漏洞面视角）**：**Vulmap / Wes / WindowsVulnScan** 针对漏洞面；其他方法在不同层面
- **流程**：`systeminfo` 拿系统信息/已装补丁 → 补丁筛选工具比对 → 列出**缺的补丁** → 对应可打的 exploit
- 我用的 **WES-NG**（Windows Exploit Suggester Next Generation）已装进 SecurityTools（见文末），`wes.py systeminfo.txt` 直接输出缺的 KB → 关联 CVE/EXP

## 三、命令类提权（案例3）

| 命令 | 用法 | 说明 |
|------|------|------|
| **at** | `at 15:13 /interactive cmd.exe` | **计划任务**提权——老系统（XP/2003）可用；at 已被 schtasks 取代，现网基本失效，但老靶机还能用 |
| **sc** | `sc Create syscmd binPath= "cmd /K start" type= own type= interact` → `sc start syscmd` | **创建服务**提权——binPath 指向要执行的东西，`type=own` + `interact`，`start` 触发，以 SYSTEM 权限跑 |
| **ps (psexec)** | `psexec.exe -accepteula -s -i -d notepad.exe` | **PsExec** 提权——`-s` 用 SYSTEM 权限跑，`-i` 交互，`-d` 不等待（需已 get 高权限/有凭据，或作为横向渗透工具） |

- 共同思路：**把命令以 SYSTEM / 高权限身份执行** —— at 靠计划任务、sc 靠服务、ps 靠 psexec
- 关联案例：**CVE-2020-0787 BitsArbitraryFileMoveExploit**（BitLocker/BITS 漏洞，也是一种拿权限的姿势）

## 四、数据库提权（案例2）

- **判断用哪种数据库提权** + 数据库提权利用条件
- MSF 结合云服务器搭建**组合拳**（拿 shell 后 MSF 上线，再联动提权）
- 关联之前学的：高权限注入（MSSQL `xp_cmdshell` / MySQL UDF 等）

## 五、思路点总结（课程三句）

1. 提权方法有部分**能跨环境通用**，也有部分**只适配特定环境**
2. 提权方法有**操作系统版本区分**——系统特性决定方法的可利用面
3. 提权方法有部分**需要特定环境**（数据库、第三方等）

## 疑问

1. ❓ WES-NG 的漏洞库怎么更新？CN 网络下 `wes.py --update` 能通吗？
2. ❓ at 是老系统废弃命令；sc 和 psexec 在 Win7/Win10 上还有效吗？适用边界？
3. ❓ 数据库提权（MSSQL/MySQL）具体利用条件？什么时候走数据库提权而不是系统提权？
4. ❓ CVE-2020-0787 BitsArbitraryFileMove 的具体利用链？

## 关联笔记

- [2026-08-25(续3)-权限提升概述.md](./2026-08-25(续3)-权限提升概述.md) — 提权概述（本课是③ 服务器系统 OS 分支的 Windows 落地）
- [2026-07-27-高权限注入与文件操作.md](./2026-07-27-高权限注入与文件操作.md) — 数据库提权基础
- [2026-08-15-DC1靶机渗透实战.md](./2026-08-15-DC1靶机渗透实战.md) — Linux 提权对照（Windows 这边是 at/sc/ps）

> ⚠️ 声明：仅限授权环境（靶场/CTF/授权渗透）中测试，所有 Payload 只用于验证漏洞存在。
