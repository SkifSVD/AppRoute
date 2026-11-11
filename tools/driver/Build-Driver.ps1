#Requires -Version 7
<#
    Сборка драйвера approute-wfp.sys (#18) и тестовая подпись.

    Нужен WDK (заголовки km и библиотеки ядра). Драйвер собирается напрямую cl/link из Visual
    Studio — без интеграции WDK в Visual Studio. Основная сборка (build.ps1, CMake) его не
    затрагивает: на машинах без WDK драйвер не собирается. В CI драйвер собирается отдельным
    шагом, если на runner'е есть WDK.

    Тестовая подпись: самоподписанный сертификат «AppRoute Test Signing» в хранилище текущего
    пользователя (создаётся при первом запуске). Такой драйвер Windows загружает только в
    тестовом режиме (bcdedit /set testsigning on), который включает сам пользователь. Сертификат
    не добавляется в доверенные корневые — это не нужно для тестового режима.

    -Package (#51): пакет для подписи Microsoft (attestation signing, см. docs/driver-signing.md):
    build\driver\package\approute-wfp\ (.sys без тестовой подписи, .inf с DriverVer, .pdb),
    проверка InfVerif и build\driver\approute-wfp.cab. -CabCertThumbprint подписывает CAB
    EV-сертификатом владельца аккаунта Partner Center (из хранилища текущего пользователя или
    токена); без него CAB остаётся неподписанным — так его и отправлять нельзя.

    Примеры:
      ./tools/driver/Build-Driver.ps1                → build\driver\approute-wfp.sys
      ./tools/driver/Build-Driver.ps1 -Package       → и build\driver\approute-wfp.cab
      ./tools/driver/Build-Driver.ps1 -Package -CabCertThumbprint <SHA1> -TimestampUrl <URL>
#>
param(
    [switch]$NoSign,
    [switch]$Package,
    [string]$CabCertThumbprint,
    [string]$TimestampUrl
)
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

$signtool = Get-ChildItem "$kits\bin" -Recurse -Filter signtool.exe | Where-Object FullName -match '\\x64\\' |
    Sort-Object FullName -Descending | Select-Object -First 1

# --- Пакет для attestation signing (#51) — до тестовой подписи: Microsoft подписывает .sys сам
if ($Package) {
    $pkg = Join-Path $out 'package\approute-wfp'
    Remove-Item -Recurse -Force (Join-Path $out 'package') -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $pkg | Out-Null
    Copy-Item $sys, "$out\approute-wfp.pdb" $pkg

    # DriverVer: дата сборки и версия AppRoute по тегам выпусков (#63, cmake/GitVersion.cmake): x.y.z → x.y.z.0
    $lists = Get-Content (Join-Path $root 'CMakeLists.txt') -Raw
    if ($lists -notmatch 'project\(AppRoute\s+VERSION\s+(\d+\.\d+\.\d+)') { throw 'Не найдена версия в CMakeLists.txt' }
    $cmake = (Get-Command cmake -ErrorAction SilentlyContinue)?.Source
    if (-not $cmake) { $cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' }
    $version = (& $cmake "-DSOURCE_DIR=$root" "-DBASE_VERSION=$($Matches[1])" -P (Join-Path $root 'cmake\GitVersion.cmake') |
        Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -or $version -notmatch '^\d+\.\d+\.\d+$') { throw 'Не удалось вычислить версию' }
    $driverVer = "DriverVer   = $((Get-Date).ToString('MM/dd/yyyy', [cultureinfo]::InvariantCulture)),$version.0"
    $inf = Get-Content (Join-Path $root 'src\driver\approute-wfp.inf') -Raw
    if ($inf -notmatch '(?m)^DriverVer\s*=.*$') { throw 'В approute-wfp.inf нет строки DriverVer' }
    $inf = $inf -replace '(?m)^DriverVer\s*=.*$', $driverVer
    [IO.File]::WriteAllText((Join-Path $pkg 'approute-wfp.inf'), $inf, [Text.Encoding]::ASCII)

    $infverif = Get-ChildItem "$kits\Tools" -Recurse -Filter infverif.exe | Where-Object FullName -match '\\x64\\' |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $infverif) { throw 'Не найден infverif.exe (WDK, Windows Kits\10\Tools)' }
    & $infverif.FullName /w /v (Join-Path $pkg 'approute-wfp.inf')
    if ($LASTEXITCODE) { throw "InfVerif нашёл ошибки в approute-wfp.inf ($LASTEXITCODE)" }

    # CAB: файлы драйвера в подпапке approute-wfp — так требует Partner Center
    $cab = Join-Path $out 'approute-wfp.cab'
    Remove-Item $cab -ErrorAction SilentlyContinue
    $ddf = Join-Path $out 'package\approute-wfp.ddf'
    @(
        '.OPTION EXPLICIT'
        '.Set CabinetFileCountThreshold=0', '.Set FolderFileCountThreshold=0', '.Set FolderSizeThreshold=0'
        '.Set MaxCabinetSize=0', '.Set MaxDiskFileCount=0', '.Set MaxDiskSize=0'
        '.Set CompressionType=MSZIP', '.Set Cabinet=on', '.Set Compress=on'
        '.Set CabinetNameTemplate=approute-wfp.cab'
        ".Set DiskDirectoryTemplate=`"$out`""
        ".Set RptFileName=`"$out\package\approute-wfp.rpt`""
        ".Set InfFileName=`"$out\package\approute-wfp.ddf.inf`""
        '.Set DestinationDir=approute-wfp'
        "`"$pkg\approute-wfp.inf`""
        "`"$pkg\approute-wfp.sys`""
        "`"$pkg\approute-wfp.pdb`""
    ) | Set-Content -Path $ddf -Encoding ascii
    & makecab.exe /F $ddf | Out-Null
    if ($LASTEXITCODE -or -not (Test-Path $cab)) { throw "makecab не создал CAB ($LASTEXITCODE)" }

    if ($CabCertThumbprint) {
        $tsArgs = if ($TimestampUrl) { @('/tr', $TimestampUrl, '/td', 'SHA256') } else { @() }
        & $signtool.FullName sign /fd SHA256 /sha1 $CabCertThumbprint @tsArgs $cab
        if ($LASTEXITCODE) { throw "Подпись CAB не удалась ($LASTEXITCODE)" }
    } else {
        Write-Warning 'CAB не подписан: для отправки в Partner Center подпишите его EV-сертификатом (-CabCertThumbprint)'
    }
    Write-Host "Пакет: $cab"
}

if (-not $NoSign) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq 'CN=AppRoute Test Signing' |
        Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=AppRoute Test Signing' `
            -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(2)
    }
    & $signtool.FullName sign /q /fd SHA256 /sha1 $cert.Thumbprint /s My $sys
    if ($LASTEXITCODE) { throw "Подпись не удалась ($LASTEXITCODE)" }
}
Write-Host "Готово: $sys"
