@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x86 -host_arch=x64 >nul
if not exist prepared mkdir prepared
cl /nologo /W4 /WX /O2 /MT /LD wb_video.c /Fe:prepared\WBVideo.dll /link /DEF:wb_video.def /MACHINE:X86 user32.lib
exit /b %errorlevel%
