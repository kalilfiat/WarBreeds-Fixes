@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x86 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
if not exist prepared mkdir prepared
cl /nologo /W4 /WX /EHsc /O2 /MT /LD wb_zoom.cpp /Fe:prepared\WBZoom.dll /link /DEF:wb_zoom.def /MACHINE:X86 user32.lib
exit /b %errorlevel%
