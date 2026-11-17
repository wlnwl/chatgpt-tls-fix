# ChatGPT TLS Fix

面向 Android 官方 ChatGPT App 的 **LSPosed 证书校验兼容实验模块**。
用于排查或临时缓解可信网络／代理环境下出现的“非预期 SSL 证书”等连接问题。

本项目是第三方个人项目，与 OpenAI、ChatGPT 或 LSPosed 官方无隶属或背书关系。
**它通过放宽部分证书验证来尝试恢复连接，不会修复网络上错误证书的根本原因。**

## 安装包

从 [Releases](https://github.com/wlnwl/chatgpt-tls-fix/releases) 下载 APK。
每个版本附有 `SHA256SUMS.txt`，可核对下载文件的 SHA-256。
源码采用 MIT 许可证；编译依赖 Xposed API 不打包进 APK。

## 使用条件与步骤

- 已 Root 的 Android 设备，以及正常工作的 LSPosed。
- 模块最低 Android 9；ChatGPT 自身的系统要求另行适用。
- 安装官方 ChatGPT App，包名为 `com.openai.chatgpt`。

1. 安装构建产物 `ChatGPT-TLS-Fix-1.2.apk`。
2. 打开 LSPosed → 模块 → **ChatGPT TLS Fix**，启用模块。
3. 作用域只勾选 **ChatGPT**，无需勾选系统框架或其他 App。
4. 强行停止 ChatGPT 后重新打开，再尝试加载会话／聊天。

不需要 Frida、电脑连接或重打包 ChatGPT。正常情况下重启目标 App 即可应用。
模块没有独立桌面界面，启停通过 LSPosed 管理。

**停用／撤销：** 在 LSPosed 中关闭模块，再强行停止并重新打开 ChatGPT；
也可以卸载包名为 `local.chatgpt.tlsfix` 的模块。

## 工作原理与作用范围

模块入口首先检查包名，只处理 `com.openai.chatgpt`。
即使误选其他作用域，代码也会拒绝对其他包安装 Hook。
在目标进程内，仅处理以下域名本身及其子域名：

```text
chatgpt.com
openai.com
oaistatic.com
oaiusercontent.com
```

| Hook 点 | 行为 |
| --- | --- |
| Conscrypt `TrustManagerImpl.verifyChain` | 先执行原方法；指定域名发生 `CertificateException` 且存在证书链时，返回传入的证书链 |
| Cronet `X509Util.verifyServerCertificates` | 先执行原方法；指定域名返回非零状态且证书可解析时，构造成功的验证结果 |

1.2 版另修正 ChatGPT `1.2026.307`（versionCode `2630718`）的一处错误分类：
这个版本会将 `SSLHandshakeException` 归为全局证书错误，包括尚未取得证书时的 EOF、
连接重置和超时。模块仅在完整的有界异常链明确属于这些传输故障时，阻止本次错误映射
写入全屏证书错误状态。原请求仍然失败，原有错误处理和重试仍继续执行。
证书异常、证书路径验证失败、公钥固定、主机名或信任错误不满足此规则。
未知版本、反射结构不匹配、异常链过长或循环时均保留应用原行为。
此修正不代表网络请求成功，也不能修复不可达的代理节点。

其他域名维持原验证结果。模块不修改系统证书、ChatGPT APK、VPN、代理或 DNS 配置。
它未覆盖所有 native 网络库、混淆后的自定义校验及证书固定实现，不能保证绕过所有 SSL 检查。

## 安全与隐私

**启用后，指定域名的部分不可信证书可能被接受。**
因此网络或代理有机会解密相关连接，包括登录凭据和聊天内容。
请只在自己控制或明确可信的网络／代理上按需使用；不再需要时停用。
更长期的解决方式是修复证书链、代理或网络配置。

模块本身没有申请网络、存储或其他 Android 权限；没有采集、上传或保存请求正文、
聊天内容、Cookie、访问令牌和账号信息的代码。
1.1 版在 LSPosed 日志与 Android `ChatGPT-TLS` 标签中输出结构化 JSON。
失败记录在修改结果之前产生，包含验证后端、目标域名、原始状态、异常类型，
以及有界的证书主体、签发者、有效期与 SHA-256 指纹；不记录完整证书、私钥、异常原始消息或请求内容。
成功、失败、自检事件分别限流，持续汇总计数，成功流量不会耗尽失败事件的额度。
事件可能包含目标域名和证书元数据，请在分享日志前自行检查。

公开源码和 Release 不包含设备 IP／ADB 地址、设备标识、个人账号数据、运行日志、
原始 ChatGPT 安装包、订阅／代理配置、签名私钥或开发电脑的绝对路径。
APK 中包含用于验证安装包签名的公开证书，这是 Android 签名格式的一部分。

## 自动测试与日志

先运行宿主机回归测试（需 JDK），再构建签名 APK：

```powershell
./test.ps1
./build.ps1 -KeystorePath <private-keystore-path> -KeyAlias local
```

在已经授权 ADB 和 root 的目标设备上运行自动安装、自检和真实启动检查：

```powershell
python ./test-device.py --adb <adb-path> --serial <device-serial>
```

此命令会备份已安装的模块 APK、覆盖安装当前版本，并重启 ChatGPT 两次。
首次启动在 ChatGPT 私有缓存中放置一次性 `chatgpt-tlsfix-selftest.request` 文件，1.2 版内容必须为 `v1.2`。
模块消费并删除请求后，直接调用真实 Conscrypt/Cronet 校验方法：
先用原始方法验证自签名测试证书被拒绝，再验证 Hook 处理结果与日志；同时检查域名范围之外仍拒绝、
有效受信链保持成功及握手异常观察器。自检不访问网络，不安装根证书，APK 仅包含公开测试证书。
测试日志带 `source=self_test`，不会被当作真实服务器证书事件。

若安装包中的 Cronet 原始校验器直接抛异常，自检会明确输出 `self_test_capability=original_verifier_throws`，
改为验证异常被记录且原样保留，不把这个结果表述成 Cronet 绕过成功。
Cronet 非零状态改写分支另由宿主机测试覆盖。

第二次启动不放置请求文件，观察真实运行 35 秒，输出 `source=live` 日志和汇总。
证据写入忽略目录 `build/device-test-<UTC时间>/`，脚本失败时返回非零退出码。
不会变更 VPN、代理分组、DNS、系统证书或 ChatGPT 数据。
可加 `--require-recovery`，额外要求输入框出现、没有证书错误页，且观察到
`android.chat.openai.com` 的原始 TLS 校验成功，以及本次进程启动后应用日志中的 HTTP 2xx 响应。
界面检查要求 ChatGPT 自身的输入框与语音入口，避免把其他应用的输入框误判为恢复。
HTTP 证据仅保存时间、主机名和状态码，不保存完整 URL、查询参数或内容。
该检查不发送聊天消息，不能证明生成回复成功。

重点事件：

| event | 含义 |
| --- | --- |
| `verification_failed` | 原始验证器确实拒绝，含异常类型或 Cronet 原始状态 |
| `verification_bypassed` | 在既有域名与入口范围内，已替换失败结果；不代表对端可信 |
| `verification_skipped` / `hook_error` | 未处理或处理时发生内部异常，原结果应保持 |
| `handshake_exception` | 观察到握手异常构造；可能没有收到证书，不能据此宣称发生证书替换 |
| `summary` | 各事件累计计数与限流情况 |
| `self_test_assert` / `self_test_complete` | 一次性本地自检结果 |
| `guard_registered` / `guard_skipped` | 当前应用版本的传输错误分类修正已注册，或因不满足条件而保留原行为 |
| `transport_error_state_suppressed` | 明确的传输故障未被写成全屏证书错误；原网络请求仍失败 |

`hook_registered` 仅代表注册成功。判断模块是否真的处理过失败证书，应关联同一调用的
`verification_failed` 与 `verification_bypassed`，并先检查 `source` 是 `live` 还是 `self_test`。

## 历史验证与限制

1.0 版本在以下组合上完成安装和运行检查：

- Android 16 / ARM64
- LSPosed 2.2.1
- ChatGPT 1.2026.307

已确认 APK 签名有效、模块随 ChatGPT 启动加载、两个 Hook 各成功注册一个，
以及启用模块后加载会话与聊天正常。

**尚未在受控条件下复现最初的证书错误，也未记录到失败证书被实际放行。**
因此这些检查不能证明模块修复了原始报错，也不代表其他系统或 ChatGPT 版本兼容。
上游更新可能使 Hook 失效。

在 LSPosed 模块日志中搜索 `[ChatGPT-TLS]` 可检查加载状态，例如：

```text
[ChatGPT-TLS] loaded v1.0 process=com.openai.chatgpt
[ChatGPT-TLS] Conscrypt hooks=1
[ChatGPT-TLS] Cronet hooks=1
```

若出现 `unavailable` 或 Hook 数量为 0，请检查目标版本。
`certificate failure bypassed` 才代表对应代码实际放行了一次失败验证。
模块不会绕过账号登录、订阅权限、服务端访问限制或修复服务器故障。

## 从源码构建

Windows / PowerShell，准备 JDK 21（或兼容 JDK）、Android SDK Platform 35 和
Build Tools 35.0.0。可通过 Android SDK Manager 安装这些组件。

设置 `JAVA_HOME` 与 `ANDROID_SDK_ROOT`（也支持 `ANDROID_HOME`），然后执行：

```powershell
./build.ps1
```

脚本从 Xposed 官方 Maven 地址下载 API 82 并检查固定 SHA-256。
仅将本项目编译后的类写入 APK，不会将 Xposed API 实现打包进去。
输出为 `out/ChatGPT-TLS-Fix-1.2.apk`，版本名由 Manifest 读取，脚本最后执行签名校验。

首次构建会在忽略目录 `.local/` 中生成开发签名密钥，使用公开的开发密码 `android`；
请勿将该密钥当作生产用途密钥。后续构建复用它以便覆盖安装。
自建 APK 与公开 Release 使用不同密钥时，需要先卸载原模块，才能安装自建版。
发布维护者应保管自己的签名私钥，私钥不随仓库分发。

也可指定现有密钥（设置环境变量 `TLSFIX_STORE_PASS` 和 `TLSFIX_KEY_PASS`，避免在命令行填写密码）：

```powershell
./build.ps1 -KeystorePath <private-keystore-path> -KeyAlias <alias>
```

构建产物、密钥、下载依赖和日志均已加入 `.gitignore`。

## 参考

- [LSPosed 模块作用域说明](https://github.com/LSPosed/LSPosed/wiki/Module-Scope)
- [Xposed API](https://api.xposed.info/)
