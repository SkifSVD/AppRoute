#Requires -Version 7
#Requires -RunAsAdministrator
<#
    Виртуальная машина Hyper-V для проверки драйвера approute-wfp.sys (#18).

    Неподписанный драйвер Windows загружает только в тестовом режиме (testsigning), а его не
    стоит включать на рабочей системе. Поэтому драйвер проверяется в отдельной ВМ.

    Что делает скрипт: создаёт ВМ 2-го поколения (TPM, 4 ГБ памяти, 2 процессора, диск 64 ГБ),
    подключает её к «Default Switch» (NAT через сеть компьютера), вставляет ISO и включает
    службу гостевого копирования (Copy-VMFile). Существующую ВМ с тем же именем не трогает.

    Пример:  ./tools/vm/New-TestVm.ps1 -Iso D:\iso\Win11_Eval.iso
    После установки Windows — ./tools/vm/New-TestVm.ps1 -Name AppRoute-Test -AfterInstall
    (выключает Secure Boot ВМ: с ним тестовый режим не работает).
#>
param(
    [string]$Iso,
    [string]$Name = 'AppRoute-Test',
    [string]$Path = (Join-Path $env:PUBLIC 'Documents\Hyper-V\AppRoute'),
    [switch]$AfterInstall
)
$ErrorActionPreference = 'Stop'

if ($AfterInstall) {
    $vm = Get-VM -Name $Name
    if ($vm.State -ne 'Off') {
        throw "Сначала выключите ВМ «$Name» (Пуск → Завершение работы внутри неё)."
    }
    # Тестовый режим загрузки игнорируется при включённой безопасной загрузке
    Set-VMFirmware -VMName $Name -EnableSecureBoot Off
    Write-Host "Secure Boot ВМ «$Name» выключен. Запустите ВМ и внутри неё, в терминале администратора:"
    Write-Host '    bcdedit /set testsigning on'
    Write-Host 'затем перезагрузите ВМ — в углу рабочего стола появится надпись «Тестовый режим».'
    return
}

if (-not $Iso -or -not (Test-Path $Iso)) {
    throw 'Укажите ISO Windows 11: -Iso путь\к\файлу.iso'
}
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    throw "ВМ «$Name» уже есть — выберите другое имя (-Name) или удалите её в диспетчере Hyper-V."
}
$switch = Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue
if (-not $switch) {
    throw 'Не найден виртуальный коммутатор «Default Switch» (он создаётся вместе с Hyper-V).'
}

New-Item -ItemType Directory -Force -Path $Path | Out-Null
$vhd = Join-Path $Path "$Name.vhdx"
New-VM -Name $Name -Generation 2 -MemoryStartupBytes 4GB -NewVHDPath $vhd -NewVHDSizeBytes 64GB `
    -SwitchName 'Default Switch' -Path $Path | Out-Null
Set-VMProcessor -VMName $Name -Count 2
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $true -MinimumBytes 2GB -MaximumBytes 6GB
# Windows 11 требует TPM 2.0 и безопасную загрузку при установке
Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
Enable-VMTPM -VMName $Name
Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
$dvd = Add-VMDvdDrive -VMName $Name -Path $Iso -Passthru
Set-VMFirmware -VMName $Name -FirstBootDevice $dvd
# Копирование файлов в ВМ без общей папки: Copy-VMFile
Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'
Set-VM -Name $Name -AutomaticCheckpointsEnabled $false -CheckpointType Standard

Write-Host "ВМ «$Name» создана: $Path"
Write-Host 'Дальше:'
Write-Host "  1. Откройте её в диспетчере Hyper-V (или vmconnect localhost $Name), запустите и нажмите"
Write-Host '     любую клавишу, когда появится «Press any key to boot from CD or DVD».'
Write-Host '  2. Установите Windows (учётная запись — локальная, ключ продукта не нужен).'
Write-Host "  3. Выключите ВМ и выполните: ./tools/vm/New-TestVm.ps1 -Name $Name -AfterInstall"
Write-Host '  4. Сделайте контрольную точку «чистая система» — к ней удобно возвращаться после проверок.'
