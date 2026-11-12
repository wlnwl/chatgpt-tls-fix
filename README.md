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

1. 安装 Release 中的 `ChatGPT-TLS-Fix-1.0.apk`。
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

其他域名维持原验证结果。模块不修改系统证书、ChatGPT APK、VPN、代理或 DNS 配置。
它未覆盖所有 native 网络库、混淆后的自定义校验及证书固定实现，不能保证绕过所有 SSL 检查。

## 安全与隐私

**启用后，指定域名的部分不可信证书可能被接受。**
因此网络或代理有机会解密相关连接，包括登录凭据和聊天内容。
请只在自己控制或明确可信的网络／代理上按需使用；不再需要时停用。
更长期的解决方式是修复证书链、代理或网络配置。

模块本身没有申请网络、存储或其他 Android 权限；没有采集、上传或保存请求正文、
聊天内容、Cookie、访问令牌和账号信息的代码。
模块记录 LSPosed 加载状态、Hook 数量，以及每进程最多 30 条证书事件；
事件可能包含目标域名和原验证状态，请在分享日志前自行检查。

公开源码和 Release 不包含设备 IP／ADB 地址、设备标识、个人账号数据、运行日志、
原始 ChatGPT 安装包、订阅／代理配置、签名私钥或开发电脑的绝对路径。
APK 中包含用于验证安装包签名的公开证书，这是 Android 签名格式的一部分。

## 已验证情况与限制

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
输出为 `out/ChatGPT-TLS-Fix-1.0.apk`，脚本最后执行签名校验。

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
