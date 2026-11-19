# 风起工具箱 逆向分析

对 `风起工具箱.exe` 的静态分析工程。全部反编译在 GitHub Actions 的 Windows runner 上完成，本地只做常量解析。

## 样本

| 项 | 值 |
| --- | --- |
| 文件名 | 风起工具箱.exe |
| 大小 | 6,576,128 字节 |
| MD5 | d392fd01b2be70279f0bf25185e24d93 |
| SHA-256 | f2fc752ce9f667fe7511da2e64939210c81956685067127176ae883b103128c2 |
| 格式 | PE32+ (GUI) x86-64, 9 节 |

## 技术栈

不是原生 C/C++ 程序，是 Go 语言写的 WebView2 桌面外壳。

- Go 版本：`go1.22.5`（`\xff Go buildinf:` 段读出）
- 模块：`fengqi-toolbox-webview`
- 关键依赖：`github.com/jchv/go-webview2`（WebView2 绑定）、`github.com/jchv/go-winloader`（系统 DLL 动态装载）
- UI：内嵌单文件 HTML（`.data` 偏移 5709312，131,133 字节，`<!DOCTYPE html>` 到 `</html>`），前端调 `window.rpcInvoke(action, json)` 与 Go 侧通信
- 无 UPX 加壳，无 .NET，无 PyInstaller/Nuitka

## 函数表恢复

Go 二进制保留 pclntab，即使 stripped 也能全量恢复符号名。

- pclntab 位于文件偏移 `0x3bc1e0`，magic `0xfffffff1`
- 符号表：`nfunc=5945`，`nfiles=602`，`textstart=0x401000`（ImageBase `0x400000`）
- `functab` 起点 = `pclntab + pcln_off`，其中 `pcln_off = 0x106d40`
- `_func` 基址 = `pclntab + pcln_off + funcoff`（funcoff 相对 functab，不是相对 pclntab —— 这是踩过的坑）
- `funcnametab` 起点 = `pclntab + funcname_off`，`funcname_off = 0x60`
- 包名统计 1519 个，`main.*` 项目自有函数 113 个

解析脚本：`tools/go_strings.py`

## 反编译

`ghidra_scripts/` 下两个 Ghidra 脚本，在 Windows runner 上跑：

1. `ApplyGoNames.java`：把 pclntab 里的 5945 个函数名按地址写进 Ghidra 数据库。结果：新建 712 个函数、重命名 5910 个、失败 35 个。
2. `DecompileShard.java`：按地址排序后取模分片，逐函数 `DecompInterface.decompileFunction`，输出到 `shard_NN.c`。

流水（`.github/workflows/decompile.yml`）：

- `prepare`：静态预检 → 拉最新 Ghidra → 无分析导入 → 注入 Go 符号名 → 全量自动分析（单函数超时 7200s）→ 打包 Ghidra 工程
- `decompile`：8 个 matrix 分片并行反编译，每片单函数超时 180s
- `finalize`：合并分片、建索引、上传 artifact、把结果提交回仓库 `results/`

产出：

- 5991 个函数块，约 14 MB C 伪代码，分布在 8 个分片
- 失败 1 个（`UN_00735ce1`，1 字节的孤立地址）
- `results/index.txt` 是函数索引，`results/failed.txt` 是失败清单

## 后端 RPC 接口

从前端 `callApi(...)` 提取，共 33 个动作：

```
ai_chat                      cancel_virus_scan        check_disk_safe
clean_residuals              execute_clean            get_clean_categories
get_disks                    get_popup_data           get_processes
get_services                 get_software             get_startups
get_sysinfo                  get_system_settings      kill_process
list_quarantine              native_drop_zone         open_setting
pick_files                   quarantine_threat        resolve_system_setting_intent
restore_quarantine           scan_residuals           set_context
shred_file                   simulate_popup_block     start_speed_test
start_virus_scan             system_ai_execute        toggle_popup_rule
toggle_service               toggle_startup           uninstall_software
```

Go 侧对应 `main.(*ApiDispatcher).HandleRpc`，按 `cmd` 分发。

## 功能模块

一级导航三类：系统属性、系统辅助、工具辅助。

工具辅助下 9 个功能页：

| 页面 | 说明 |
| --- | --- |
| 服务管理 | SCM 服务状态与启动类型切换，带受保护服务白名单 |
| 启动项管理 | `HKCU\Software\...\Run` 与 `HKLM\SOFTWARE\...\Run` 键值枚举与改写 |
| 系统清理 | 缓存/临时文物件枚举与清理（缩略图数据库 `thumbcache_*.db` 等） |
| 系统设置直达 | 内置设置目录，跳 `ms-settings:`、`control.exe`、`regedit.exe`、`diskmgmt.msc` 等 |
| 网络测速 | 下行/上行/Ping/抖动，下行测试打 `speed.cloudflare.com/__down` |
| 磁盘管理 | 分区枚举、只读诊断（FAT/MFT 索引、坏道检查，明确标注「无损检测」） |
| 软件卸载 | 注册表卸载信息枚举 + 残留扫描 + 调标准卸载命令 |
| 弹窗拦截 | 规则表 + 白名单 + 拦截记录，目标进程名有 `AdPushCenter.exe`、`AdPrompt.exe`、`MiniNewsTray.exe` |
| 文件粉碎 | DoD 风格覆写，仅支持普通文件，拒绝目录 |
| 病毒扫描 | 全盘扫描 + 隔离区管理 |

## AI 助手

只在「系统辅助」页可用。前端固定的 system prompt：

> 你是风起工具箱的系统辅助助手。只处理任务管理、服务、启动项、清理与 Windows 设置直达相关操作。涉及修改系统设置时，先明确目标设置并等待用户选择「位置指引」或「确认执行」。

二进制里另有一份更严格的约束串：

> 仅可使用提供的系统只读工具获取信息 …或使用 system_prepare_action 生成待用户确认的动作提案 …严禁任意 shell、网络访问和直接修改系统、任何终止进程、修改服务或启动项、打开设置都必须先生成提案并等待用户确认

- 端点：`https://allgpt.xianyuw.cn/v1/chat/completions`（OpenAI 兼容）
- 模型：`qwen3.5-122b`
- API Key 存 `ai-key.dpapi`
- 动作执行走 `main.ExecutePendingAIAction`：先建提案入 map，用户确认后按 type 分派到 `KillProcessByPID` / `OpenAllowedSetting` / `ChangeSystemService` / `ChangeSystemStartup` / `ShredFileDoD`
- 有工具调用次数上限（「AI 工具调用次数超过限制」）

## 本地数据保护

- `main.ProtectLocalData` / `main.UnprotectLocalData`：Go 侧 `golang.org/x/sys/windows` 的 `LazyProc.Call` 调 `CryptProtectData` / `CryptUnprotectData`（DPAPI，当前用户作用域），配合 `LocalFree` 释放。因此这两个函数在 Ghidra 里看不到 `CryptProtectData` 直接导入 —— 走的是 `GetProcAddress` 动态解析。
- AI Key 落盘：`os.UserConfigDir()` → 目录 → `ai-key.dpapi`，写临时文件再 `Rename` 原子替换
- 隔离区主密钥：`master.key.dpapi`
- 隔离文件加密：`crypto/aes.NewCipher` + `crypto/cipher.NewGCMWithNonceAndTagSize` + `crypto/rand.Read`，AES-256-GCM，随机 nonce
- 隔离文件上限有大小限制，恢复时校验路径必须与索引记录一致

## 系统操作面

提权/敏感操作都通过 `golang.org/x/sys/windows` 的 LazyProc 动态解析调用，PE 导入表里看不到，静态扫描容易漏：

- 服务：`OpenSCManager` / `ControlService` / `ChangeServiceConfig` / `QueryServiceStatusEx` / `QueryServiceConfig2W` / `SetServiceStatus` / `RegisterEventSourceW`
- 注册表：`RegCreateKeyExW` / `RegQueryValueExW` / `RegQueryInfoKeyW` / `RegDeleteValueW` / `RegCloseKey`
- 进程：`OpenProcess` / `OpenProcessToken` / `Process32FirstW` / `CreateToolhelp32Snapshot` / `TerminateProcess` / `AssignProcessToJobObject` / `CreateJobObjectW`
- 令牌/安全：`DuplicateTokenEx` / `ImpersonateSelf` / `OpenThreadToken` / `IsValidSid` / `CheckTokenMembership` / `AllocateAndInitializeSid` / `GetSecurityInfo` / `SetSecurityInfo` / `SetEntriesInAclW` / `BuildSecurityDescriptorW`
- 卷/磁盘：`FindFirstVolumeW` / `FindNextVolumeW` / `SetVolumeMountPointW` / `DeviceIoControl` / `SetVolumeLabelW`
- 驱动签名校验：`WinVerifyTrustEx` / `CryptQueryObject` / `CryptAcquireContextW` / `CertOpenSystemStoreW`
- 系统路径：`SHGetKnownFolderPath` / `GetUserProfileDirectoryW` / `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

## 仓库结构

```
.github/workflows/decompile.yml   CI 流水（prepare / decompile×8 / finalize）
ghidra_scripts/ApplyGoNames.java  按地址批量注入 Go 符号名
ghidra_scripts/DecompileShard.java 分片全量反编译
tools/pe_info.py                  PE 节表、导入表、资源、版本信息
tools/extract_strings.py          内嵌前端提取、ASCII/UTF-8 字符串、URL/IP/路径
tools/go_strings.py               pclntab 解析，恢复全量函数名与包名
tools/summarize.py                GoReSym 输出汇总
tools/build_index.py              反编译产物函数索引
tools/extract_fn.py               按正则从分片里捞指定函数
data/                             函数表、包名表、main 函数清单
payload/fengqi.exe                样本
results/                          CI 回写：C 伪代码、索引、字符串、前端 HTML、日志
```

## 复现

```bash
gh workflow run decompile.yml
```

或直接在 Actions 页面点 Run workflow。产物看 `fengqi-decompiled-full` artifact，同时会提交到 `results/`。