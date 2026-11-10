#Requires -Version 7
<#
    Сборка драйвера approute-wfp.sys (#18) и тестовая подпись.

    Нужен WDK (заголовки km и библиотеки ядра). Драйвер собирается напрямую cl/link из Visual
    Studio — без интеграции WDK в Visual Studio. Основная сборка (build.ps1, CMake) его не
    затрагивает: на машинах без WDK, в том числе в CI, драйвер не собирается.

    Тестовая подпись: самоподписанный сертификат «AppRoute Test Signing» в хранилище текущего
    пользователя (создаётся при первом запуске). Такой драйвер Windows загружает только в
    тестовом режиме (bcdedit /set testsigning on), который включает сам пользователь. Сертификат
    не добавляется в доверенные корневые — это не нужно для тестового режима.

    Пример: ./tools/driver/Build-Driver.ps1      → build\driver\approute-wfp.sys
#>
param([switch]$NoSign)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$out = Join-Path $root 'build\driver'
New-Item -ItemType Directory -Force -Path $out | Out-Null

# --- WDK: версия с заголовками km; общие заголовки WFP могут быть только в SDK другой версии
$kits = "${env:ProgramFiles(x86)}\Windows Kits\10"
$wdk = Get-ChildItem "$kits\Include" -Directory | Where-Object { Test-Path "$($_.FullName)\km\fwpsk.h" } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $wdk) { throw 'Не найден WDK (Windows Kits\10\Include\<версия>\km\fwpsk.h)' }
$shared = Get-ChildItem "$kits\Include" -Directory | Where-Object { Test-Path "$($_.FullName)\shared\fwpstypes.h" } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $shared) { throw 'Не найдены общие заголовки WFP (shared\fwpstypes.h) — нужен Windows SDK' }
$kmLib = "$kits\Lib\$($wdk.Name)\km\x64"

# --- Visual Studio: окружение компилятора x64
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Не найдена Visual Studio с компонентом C++' }
Import-Module (Join-Path $vs 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null

$includes = @(
    "$($wdk.FullName)\km", "$($wdk.FullName)\km\crt", "$($wdk.FullName)\shared",
    "$($shared.FullName)\shared", (Join-Path $root 'src\driver')
) | ForEach-Object { "/I$_" }
$defines = '/D_AMD64_', '/DAMD64', '/D_WIN64', '/DNTDDI_VERSION=0x0A000005', '/D_WIN32_WINNT=0x0A00',
    '/DWINVER=0x0A00', '/DNDIS_SUPPORT_NDIS6', '/DNDIS630', '/DPOOL_NX_OPTIN=1', '/DUNICODE', '/D_UNICODE'
$cflags = '/nologo', '/c', '/kernel', '/W4', '/WX', '/O2', '/Gy', '/GS', '/Zi', '/Zc:wchar_t', '/std:c17',
    '/guard:cf', "/Fo$out\driver.obj", "/Fd$out\approute-wfp.pdb"
& cl.exe @cflags @defines @includes (Join-Path $root 'src\driver\driver.c')
if ($LASTEXITCODE) { throw "Компиляция не удалась ($LASTEXITCODE)" }

$sys = Join-Path $out 'approute-wfp.sys'
$lflags = '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE,10.00', '/ENTRY:GsDriverEntry', '/NODEFAULTLIB', '/DEBUG',
    '/GUARD:CF', '/OPT:REF', '/OPT:ICF', '/RELEASE', '/MERGE:_TEXT=.text;_PAGE=PAGE', '/INTEGRITYCHECK',
    "/OUT:$sys", "/PDB:$out\approute-wfp.pdb", "/LIBPATH:$kmLib"
& link.exe @lflags "$out\driver.obj" ntoskrnl.lib hal.lib fwpkclnt.lib netio.lib BufferOverflowFastFailK.lib
if ($LASTEXITCODE) { throw "Компоновка не удалась ($LASTEXITCODE)" }

if (-not $NoSign) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq 'CN=AppRoute Test Signing' |
        Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=AppRoute Test Signing' `
            -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(2)
    }
    $signtool = Get-ChildItem "$kits\bin" -Recurse -Filter signtool.exe | Where-Object FullName -match '\\x64\\' |
        Sort-Object FullName -Descending | Select-Object -First 1
    & $signtool.FullName sign /q /fd SHA256 /sha1 $cert.Thumbprint /s My $sys
    if ($LASTEXITCODE) { throw "Подпись не удалась ($LASTEXITCODE)" }
}
Write-Host "Готово: $sys"
