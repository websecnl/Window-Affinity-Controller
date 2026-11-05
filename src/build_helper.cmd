@echo off
setlocal
cd /d "%~dp0"
where cl >nul 2>nul
if errorlevel 1 (
  echo Run this from an x64 Native Tools Command Prompt for Visual Studio.
  exit /b 1
)
if /i not "%VSCMD_ARG_TGT_ARCH%"=="x64" (
  echo This build requires the x64 Native Tools Command Prompt.
  exit /b 1
)
cl /nologo /LD /O2 /W4 /MT /EHsc affinity_helper.cpp user32.lib /link /OUT:affinity_helper.dll
if errorlevel 1 exit /b %errorlevel%
exit /b %errorlevel%
