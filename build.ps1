#Requires -Version 7
<#
    Сборка AppRoute. Ищет cmake в PATH, иначе берёт cmake из Visual Studio
    (включая Preview/Insiders).
    Пример: ./build.ps1 -Config Debug
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Config = 'Release'
)
$ErrorActionPreference = 'Stop'

$cmake = (Get-Command cmake -ErrorAction SilentlyContinue)?.Source
if (-not $cmake) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'Не найдена Visual Studio с компонентом C++ (VC.Tools.x86.x64)' }
    $cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
}

$build = Join-Path $PSScriptRoot 'build'

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

& $cmake -S $PSScriptRoot -B $build -A x64
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $cmake --build $build --config $Config
exit $LASTEXITCODE
