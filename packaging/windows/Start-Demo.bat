@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul

pushd "%~dp0"
if errorlevel 1 goto directory_failed

echo GrantTrace v2.5.1
echo 正在运行内置 Demo，请稍候。
echo Demo 仅访问本机内置模拟环境，无需安装 Python。
echo.

if not exist "%~dp0granttrace.exe" goto missing_executable

:choose_output
set "GRANTTRACE_RUN_PARENT=%~dp0granttrace-demo\session-%RANDOM%-%RANDOM%"
if exist "%GRANTTRACE_RUN_PARENT%" goto choose_output

"%~dp0granttrace.exe" demo --output-dir "%GRANTTRACE_RUN_PARENT%"
set "GRANTTRACE_EXIT=%ERRORLEVEL%"
if not "%GRANTTRACE_EXIT%"=="0" goto demo_failed

set "GRANTTRACE_HTML="
for /d %%D in ("%GRANTTRACE_RUN_PARENT%\run-*") do if exist "%%~fD\granttrace_report.html" if exist "%%~fD\granttrace_report.json" set "GRANTTRACE_HTML=%%~fD\granttrace_report.html"
if not defined GRANTTRACE_HTML goto missing_report

echo.
echo Demo 已完成。HTML 报告保存在：
echo "%GRANTTRACE_HTML%"
echo 可以双击此 HTML 文件查看报告。
if "%GRANTTRACE_DEMO_NO_OPEN%"=="1" goto finished
start "" "%GRANTTRACE_HTML%"
goto finished

:missing_executable
echo [错误] 找不到 granttrace.exe。请先完整解压 ZIP 后再双击 Start-Demo.bat。
set "GRANTTRACE_EXIT=2"
goto finished

:demo_failed
echo.
echo [错误] Demo 未能完成。请查看上方错误信息，确认 ZIP 已完整解压到可写目录。
goto finished

:missing_report
echo.
echo [错误] Demo 未生成完整报告。请查看上方信息。
set "GRANTTRACE_EXIT=2"
goto finished

:finished
echo.
echo 按任意键关闭窗口。
pause >nul
popd
exit /b %GRANTTRACE_EXIT%

:directory_failed
echo [错误] 无法进入程序目录。请先完整解压 ZIP 到可访问的目录。
echo 按任意键关闭窗口。
pause >nul
exit /b 2
