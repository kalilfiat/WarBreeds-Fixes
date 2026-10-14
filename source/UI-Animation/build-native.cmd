@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x86 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
if not exist prepared mkdir prepared
cl /nologo /W4 /WX /O2 /MT /LD wb_ui.c /Fe:prepared\WBUIAnim.dll /link /DEF:wb_ui.def /MACHINE:X86
exit /b %errorlevel%
