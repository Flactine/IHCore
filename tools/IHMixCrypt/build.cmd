@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo Run from a Visual Studio Developer Command Prompt.
  exit /b 1
)
if not exist "%~dp0bin" mkdir "%~dp0bin"
cl /nologo /std:c++17 /EHsc /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS "%~dp0main.cpp" /Fo"%~dp0bin\IHMixCrypt.obj" /Fe"%~dp0bin\IHMixCrypt.exe" /link bcrypt.lib
exit /b %errorlevel%
