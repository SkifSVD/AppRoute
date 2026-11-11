#Requires -Version 7
<#
.SYNOPSIS
    Сборка AppRoute и публикация выпуска.

.DESCRIPTION
    Ищет cmake в PATH, иначе берёт cmake из Visual Studio (включая Preview/Insiders). Собирает
    x64 и x86 (hook-DLL и помощник внедрения для 32-битных программ) в build\bin\<Config>.

    Версия (#63) считается по тегам выпусков git (cmake/GitVersion.cmake): на теге vX.Y.Z — она,
    после тега — следующий патч; "+semver: minor" / "+semver: major" в сообщении коммита поднимают
    минор или мажор. -Publish ставит тег выпуска и отправляет его в origin: без тега номер следующих
    сборок замирает.

.PARAMETER Config
    Debug или Release (по умолчанию Release).

.PARAMETER Test
    Прогнать модульные тесты (ctest) после сборки.

.PARAMETER Version
    Ручная версия X.Y.Z вместо вычисленной (хотфикс); тег выпуска при этом не ставится.

.PARAMETER Publish
    Собрать папку поставки deploy\AppRoute-<версия>\ (программы, README.txt, LICENSE) и поставить
    тег выпуска vX.Y.Z (только из main, с чистым деревом, коммит — уже в origin/main).

.PARAMETER Zip
    После -Publish упаковать поставку в deploy\AppRoute-<версия>-win-x64.zip.

.PARAMETER NoTag
    Не ставить тег выпуска после -Publish.

.PARAMETER NoTagPush
    Поставить тег локально, не отправляя в origin.

.EXAMPLE
    ./build.ps1 -Test
.EXAMPLE
    ./build.ps1 -Publish -Zip
.EXAMPLE
    ./build.ps1 -Publish -Version 0.3.1 -NoTag
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Config = 'Release',
    [switch]$Test,
    [string]$Version = '',
    [switch]$Publish,
    [switch]$Zip,
    [switch]$NoTag,
    [switch]$NoTagPush
)
$ErrorActionPreference = 'Stop'

if ($Version -and $Version -notmatch '^\d+\.\d+\.\d+$') { throw "-Version: нужен формат X.Y.Z, а не «$Version»" }
if ($Zip -and -not $Publish) { throw '-Zip — только вместе с -Publish' }
if ($Publish -and $Config -ne 'Release') { throw '-Publish — только для -Config Release' }

$cmake = (Get-Command cmake -ErrorAction SilentlyContinue)?.Source
if (-not $cmake) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'Не найдена Visual Studio с компонентом C++ (VC.Tools.x86.x64)' }
    $cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
}

$build = Join-Path $PSScriptRoot 'build'
$treeWasCleanAtStart = -not (git -C $PSScriptRoot status --porcelain)

# Версия — тем же правилом, что при сборке (cmake/GitVersion.cmake)
function Get-AppRouteVersion {
    $cmakeLists = Get-Content (Join-Path $PSScriptRoot 'CMakeLists.txt') -Raw
    if ($cmakeLists -notmatch 'project\(AppRoute\s+VERSION\s+(\d+\.\d+\.\d+)') { throw 'Не найдена версия в CMakeLists.txt' }
    $out = & $cmake "-DSOURCE_DIR=$PSScriptRoot" "-DBASE_VERSION=$($Matches[1])" "-DOVERRIDE=$Version" `
        -P (Join-Path $PSScriptRoot 'cmake\GitVersion.cmake')
    if ($LASTEXITCODE) { throw 'Не удалось вычислить версию' }
    return ($out | Select-Object -Last 1).Trim()
}

# hook-DLL может быть загружена в запущенные через AppRoute программы — перезаписать её нельзя,
# а переименовать можно. Старые копии удаляются, когда освободятся.
Get-ChildItem (Join-Path $build 'bin') -Recurse -Filter 'approute-hook*.dll.old-*' -ErrorAction SilentlyContinue |
    ForEach-Object { try { [System.IO.File]::Delete($_.FullName) } catch { } }
foreach ($dll in Get-ChildItem (Join-Path $build 'bin') -Recurse -Filter 'approute-hook*.dll' -ErrorAction SilentlyContinue) {
    try {
        $stream = [System.IO.File]::Open($dll.FullName, 'Open', 'ReadWrite', 'None'); $stream.Dispose()
    } catch {
        $old = "$($dll.FullName).old-$(Get-Date -Format 'yyyyMMddHHmmss')"
        [System.IO.File]::Move($dll.FullName, $old)
        Write-Host "$($dll.Name) занята запущенной программой — переименована в $(Split-Path $old -Leaf)"
    }
}

$override = "-DAPPROUTE_VERSION_OVERRIDE=$Version"
& $cmake -S $PSScriptRoot -B $build -A x64 $override
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $cmake --build $build --config $Config
if ($LASTEXITCODE) { exit $LASTEXITCODE }

# x86: hook-DLL и помощник внедрения для 32-битных программ — в ту же папку bin
$build32 = Join-Path $PSScriptRoot 'build32'
& $cmake -S $PSScriptRoot -B $build32 -A Win32 -DAPPROUTE_HOOK_ONLY=ON "-DAPPROUTE_BIN_DIR=$(Join-Path $build 'bin')" $override
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $cmake --build $build32 --config $Config
if ($LASTEXITCODE) { exit $LASTEXITCODE }

if ($Test) {
    $ctest = Join-Path (Split-Path $cmake) 'ctest.exe'
    & $ctest --test-dir $build -C $Config --output-on-failure
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}

if (-not $Publish) {
    exit 0
}

# --- публикация -------------------------------------------------------------------------------

$releaseVersion = Get-AppRouteVersion
$deploy = Join-Path $PSScriptRoot 'deploy'
$package = Join-Path $deploy "AppRoute-$releaseVersion"
Write-Host "Поставка AppRoute $releaseVersion → $package" -ForegroundColor Yellow
if (Test-Path -LiteralPath $package) { Remove-Item -LiteralPath $package -Recurse -Force }
New-Item -ItemType Directory -Force -Path $package | Out-Null

$bin = Join-Path $build "bin\$Config"
$files = @(
    'approute-gui.exe', 'approute-run.exe', 'approute-config.exe', 'approute-routes.exe', 'approute-dns.exe',
    'approute-inject64.exe', 'approute-inject32.exe', 'approute-hook64.dll', 'approute-hook32.dll'
)
foreach ($name in $files) {
    $file = Join-Path $bin $name
    if (-not (Test-Path -LiteralPath $file)) { throw "Нет $name в $bin" }
    $actual = (Get-Item -LiteralPath $file).VersionInfo.FileVersion
    if ($actual -ne $releaseVersion) { throw "$name собран с версией $actual, а выпуск — $releaseVersion" }
    Copy-Item -LiteralPath $file -Destination $package
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE') -Destination $package
@"
AppRoute $releaseVersion — маршрутизация трафика по приложениям (Windows 10/11 x64)

Запуск: approute-gui.exe — окно правил. Утилиты командной строки: approute-run, approute-config,
approute-routes, approute-dns (у каждой — --version и справка без параметров).

Документация: https://github.com/SkifSVD/AppRoute
"@ | Set-Content -LiteralPath (Join-Path $package 'README.txt') -Encoding UTF8
Write-Host "  Готово: $package" -ForegroundColor Green

if ($Zip) {
    $zipPath = Join-Path $deploy "AppRoute-$releaseVersion-win-x64.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Compress-Archive -Path (Join-Path $package '*') -DestinationPath $zipPath
    Write-Host "  ZIP: $zipPath" -ForegroundColor Green
}

# Тег выпуска: без него версия следующих сборок замрёт на этом номере. Невыполнимое условие —
# предупреждение с командой для ручного запуска, а не ошибка: поставка уже собрана.
$tagName = "v$releaseVersion"
$skip = $null
if ($NoTag) { $skip = 'указан -NoTag' }
elseif ($Version) { $skip = "версия задана вручную (-Version $Version)" }
elseif ((git -C $PSScriptRoot rev-parse --abbrev-ref HEAD) -ne 'main') { $skip = 'публикация не из main' }
elseif (-not $treeWasCleanAtStart) { $skip = 'дерево было грязным при запуске — в поставку ушло не то, что в коммите' }
else {
    git -C $PSScriptRoot rev-parse --verify --quiet "refs/tags/$tagName" | Out-Null
    if ($LASTEXITCODE -eq 0) { $skip = "тег $tagName уже стоит" }
    else {
        git -C $PSScriptRoot merge-base --is-ancestor HEAD origin/main 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { $skip = 'коммит ещё не в origin/main' }
    }
}
$global:LASTEXITCODE = 0
if ($skip) {
    Write-Host "Тег $tagName не поставлен: $skip." -ForegroundColor DarkYellow
    Write-Host "  Вручную: git tag -a $tagName -m `"AppRoute $releaseVersion`"; git push origin $tagName" -ForegroundColor DarkYellow
    exit 0
}
git -C $PSScriptRoot tag -a $tagName -m "AppRoute $releaseVersion"
if ($LASTEXITCODE) { Write-Host "Не удалось поставить тег $tagName" -ForegroundColor Red; exit 0 }
Write-Host "Тег $tagName поставлен." -ForegroundColor Green
if ($NoTagPush) {
    Write-Host "  Отправка отключена (-NoTagPush). Вручную: git push origin $tagName" -ForegroundColor DarkYellow
    exit 0
}
git -C $PSScriptRoot push origin $tagName
if ($LASTEXITCODE) { Write-Host "  Тег остался локальным. Повторить: git push origin $tagName" -ForegroundColor DarkYellow }
exit 0
