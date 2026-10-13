# GrantTrace 2.5.3 Windows 便携包

分发文件为 `GrantTrace-v2.5.3-Windows-x64.zip`。用户解压整个 ZIP 后双击
`Start-Demo.bat` 即可运行内置 demo，无需安装 Python 或修改系统 PATH。
程序版本为 `GrantTrace 2.5.3`；包含 main 已合并的 PR #33 授权判断、请求统计和
只读语义检查修复，以及 PR #34 具体读取路径安全修复，详见 [CHANGELOG](../CHANGELOG.md)。
推荐 Windows 10 / 11（64 位）。启动器自动打开 HTML 并打印确切路径；报告保存在
解压目录的 `granttrace-demo/session-*/run-*/`，每次运行使用新的目录。

**v2.5.3 尚未发布。** 普通用户从官方 [最新 Release](https://github.com/ysc070528/granttrace/releases/latest)
下载页面实际提供的 Windows ZIP 和 `SHA256SUMS.txt`；2026-10-13 核验时最新发布为 v2.5.2。
本轮 2.5.3 构建用于发布准备，以下构建工作流只上传 Actions artifact，
不自动修改 tag / Release 或上传 PyPI。

## 本地构建

构建环境固定为 **CPython 3.14.5 / PyInstaller 6.22.3（Windows x64）**。
使用独立虚拟环境，从仓库根目录执行；创建环境后先核对 Python 版本。
采用 PyInstaller
one-folder 构建，关闭 UPX；ZIP 包含可执行文件、依赖、demo 资源和启动器，
运行时保留解压目录结构。

```powershell
py -3.14 -m venv dist/windows-build-env
.\dist\windows-build-env\Scripts\python.exe --version
.\dist\windows-build-env\Scripts\python.exe -m pip install -r packaging/windows/requirements-build.txt
.\dist\windows-build-env\Scripts\python.exe -m pip install --no-build-isolation --no-deps .
.\dist\windows-build-env\Scripts\python.exe scripts/build_windows_portable.py
.\dist\windows-build-env\Scripts\python.exe scripts/verify_windows_portable.py --zip dist/GrantTrace-v2.5.3-Windows-x64.zip --output dist/windows-portable-verification.json
```

最终交付文件为：

- `dist/GrantTrace-v2.5.3-Windows-x64.zip`
- `dist/SHA256SUMS.txt`：记录 ZIP 的 SHA-256。
- `dist/windows-portable-build.json`：记录源码 commit、工具版本、EXE / ZIP 大小与哈希。
- `dist/windows-portable-verification.json`：记录实际验证结果，供维护者复核。

验证时使用 ZIP 解压后的程序，确认 `--version` 输出 `GrantTrace 2.5.3`，
`--help` 可用，内置 demo 能生成 HTML / JSON 报告，关闭本机服务并完整恢复数据。
发布前还需在含空格和中文的目录人工双击 `Start-Demo.bat`，确认正常完成且报告可以打开。
自动验证会实际将 ZIP 解压到仓库外的空格、中文路径，从空目录启动程序；
子进程 PATH 仅保留 Windows 系统目录，并清除 Python / 虚拟环境变量。
还核对只读 demo 无 PATCH、YAML 离线计划 0 请求、独立 TCP 端口关闭和可查询的包内进程无残留。
CI 为避免打开浏览器设置 `GRANTTRACE_DEMO_NO_OPEN=1`；正常双击仍默认打开 HTML。
暂停保留，自动验证只通过标准输入模拟按键，不隐藏程序或关闭安全软件。

## GitHub Actions 构建产物与独立验收

1. 在 PR 的 Checks 或仓库 Actions 中打开 **GrantTrace Windows portable**
   工作流（`windows-package.yml`），
   核对运行对应的 commit SHA，等待该次运行成功。
2. 下载 **GrantTrace-v2.5.3-Windows-x64** artifact，解开外层 artifact ZIP，取出内部的
   `GrantTrace-v2.5.3-Windows-x64.zip`、`SHA256SUMS.txt` 和验证 JSON。
3. 用 `Get-FileHash -Algorithm SHA256` 核对分发 ZIP 与 `SHA256SUMS.txt`，
   阅读验证 JSON，再将分发 ZIP 完整解压到新的测试目录。
4. 在没有安装 Python 的 Windows x64 环境双击 `Start-Demo.bat`，
   核对版本、报告、服务关闭和数据恢复；记录操作系统、commit 和结果。

这些步骤用于维护者验证构建产物，不会替换已经提供的 Release 附件。

本轮构建与自动验收结果记录在 [VERIFICATION.md](../VERIFICATION.md)。本地准备输出
位于 `dist/v2.5.3-windows/`；源码有未提交修改时构建 JSON 的 `source_tree_dirty` 为 true，
须在最终提交上重新取得干净 CI 制品。自动 smoke 通过 `GRANTTRACE_DEMO_NO_OPEN=1`
抑制浏览器，并经标准输入确认启动器暂停，不代表人工双击、浏览器视觉验收或干净 Windows 实测。
PR #29 的历史默认启动器验证保留在 [验证历史](history/release-verification-history.md)。
后续提交须核对各自实际 HEAD，以对应 artifact 和构建 / 验证 JSON 为准。

EXE 未签名，下载后可能出现 SmartScreen 或安全软件提示；不保证所有产品均无误报。
普通用户只从官方 GitHub Release 下载并核对 `SHA256SUMS.txt`；不关闭或绕过安全软件。
