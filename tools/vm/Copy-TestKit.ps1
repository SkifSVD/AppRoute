#Requires -RunAsAdministrator
<#
    Копирует в тестовую ВМ (New-TestVm.ps1) всё для проверки драйвера: программы AppRoute из
    build\bin\Release, драйвер build\driver\approute-wfp.sys и скрипт Test-Driver.ps1 — в
    C:\AppRouteTest внутри ВМ. ВМ должна быть запущена. Пароль ВМ не нужен (Copy-VMFile).

    Пример: ./tools/vm/Copy-TestKit.ps1             (сначала ./build.ps1 и ./tools/driver/Build-Driver.ps1)
#>
param([string]$Name = 'AppRoute-Test')
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')

$vm = Get-VM -Name $Name
if ($vm.State -ne 'Running') { throw "Запустите ВМ «$Name»." }

$files = @(Get-ChildItem (Join-Path $root 'build\bin\Release') -File |
    Where-Object { $_.Name -like 'approute-*.exe' -or $_.Name -like 'approute-hook*.dll' } |
    Where-Object Name -ne 'approute-tests.exe')
$sys = Join-Path $root 'build\driver\approute-wfp.sys'
if (-not (Test-Path $sys)) { throw 'Нет build\driver\approute-wfp.sys — соберите: ./tools/driver/Build-Driver.ps1' }
$files += Get-Item $sys
$files += Get-Item (Join-Path $PSScriptRoot 'Test-Driver.ps1')

foreach ($f in $files) {
    Copy-VMFile -Name $Name -SourcePath $f.FullName -DestinationPath "C:\AppRouteTest\$($f.Name)" `
        -FileSource Host -CreateFullPath -Force
}
Write-Host "Скопировано в ВМ «$Name», C:\AppRouteTest: $($files.Count) файлов."
Write-Host 'В ВМ: Windows PowerShell от имени администратора →'
Write-Host '    powershell -ExecutionPolicy Bypass -File C:\AppRouteTest\Test-Driver.ps1'
