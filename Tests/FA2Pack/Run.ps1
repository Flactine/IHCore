param([Parameter(Mandatory=$true)][string]$Generator)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/../..").Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('IHCore-PackTest-' + [guid]::NewGuid())
New-Item -ItemType Directory -Force "$work/src","$work/packs","$work/assets/one","$work/assets/two","$work/mismatch" | Out-Null
[IO.File]::WriteAllText("$work/assets/one/example.ini", "[Test]`r`nValue=42`r`n")
[IO.File]::WriteAllBytes("$work/assets/one/empty.bin", [byte[]]@())
[IO.File]::WriteAllBytes("$work/assets/two/binary.bin", [byte[]](0..255))
Copy-Item "$root/IHCore/ResourcePack/ResourcePack.cpp","$root/IHCore/ResourcePack/ResourcePack.h","$PSScriptRoot/Test.cpp" "$work/src"
& $Generator --seed ('12' * 32) --assets "$work/assets" --out-dir "$work/packs" --cpp-out "$work/src/Body.Encryption.cpp" --header-out "$work/src/Body.Cipher.h"
if ($LASTEXITCODE) { throw 'Generator failed' }
Copy-Item "$root/IHCore/ResourcePack/*" "$work/mismatch"
Copy-Item "$PSScriptRoot/Test.cpp" "$work/mismatch"
$vs = & "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe" -latest -property installationPath
$commands = @"
@echo off
call "$vs\VC\Auxiliary\Build\vcvars32.bat" >nul
cl /nologo /EHsc /std:c++20 /O2 /MT /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I "$root\libs\FA2Pack\include" src\Test.cpp src\ResourcePack.cpp src\Body.Encryption.cpp /Fe:test.exe /link "$root\libs\FA2Pack\lib\libcrypto.lib"
if errorlevel 1 exit /b 1
copy /y "$root\libs\FA2Pack\bin\libcrypto-1_1.dll" . >nul
test.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /MT /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I "$root\libs\FA2Pack\include" mismatch\Test.cpp mismatch\ResourcePack.cpp mismatch\Body.Encryption.cpp /Fe:mismatch.exe /link "$root\libs\FA2Pack\lib\libcrypto.lib"
if errorlevel 1 exit /b 1
mismatch.exe reject
"@
[IO.File]::WriteAllText("$work/build.cmd", $commands)
Push-Location $work
try {
    & ./build.cmd
    if ($LASTEXITCODE) { throw "Pack test failed: $LASTEXITCODE" }
} finally { Pop-Location }
Write-Host "Test artifacts: $work"
