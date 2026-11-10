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
& $cmake -S $PSScriptRoot -B $build -A x64
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $cmake --build $build --config $Config
exit $LASTEXITCODE
