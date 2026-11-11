<#
    Проверка драйвера approute-wfp.sys внутри тестовой ВМ (#18). Windows PowerShell 5.1 от имени
    администратора:  powershell -ExecutionPolicy Bypass -File C:\AppRouteTest\Test-Driver.ps1

    1. Загружает драйвер (approute-routes install-driver).
    2. Создаёт правило: curl.exe и копия PowerShell (для проверки UDP) → вторая сетевая карта ВМ;
       если есть App Installer — и winget как приложение из пакета MSIX (#45, правило по AUMID).
    3. Включает правила (approute-routes wfp) и запускает программы обычным способом, без AppRoute:
       TCP (curl) и UDP (сокет на «любом» адресе) должны выйти с адреса второй карты.
    4. Снимает правила (завершает approute-routes wfp) и проверяет, что всё вернулось.
    5. Выгружает драйвер.

    -Service: вместо шагов 1, 3–5 — служба AppRoute с драйвером (install-service --with-driver):
    правила без отдельного процесса, правка конфига на лету, остановка службы снимает правила,
    удаление службы удаляет и драйвер.
    Итог печатается; его можно целиком скопировать в чат.
#>
param([switch]$Service)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8   # вывод approute-routes — UTF-8
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$routes = Join-Path $dir 'approute-routes.exe'
$results = New-Object System.Collections.Generic.List[string]
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $line = '{0} {1}{2}' -f ($(if ($ok) { '[OK]  ' } else { '[FAIL]' }), $name, $(if ($detail) { " — $detail" } else { '' }))
    $results.Add($line); Write-Host $line
}

# --- подготовка
$bcd = (bcdedit /enum '{current}') -join "`n"
Check 'тестовый режим включён' ($bcd -match 'testsigning\s+Yes') 'bcdedit /set testsigning on и перезагрузка'
$nics = @(Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction SilentlyContinue | Sort-Object InterfaceIndex)
Check 'две сетевые карты с адресами' ($nics.Count -ge 2) "найдено: $($nics.Count)"
if ($nics.Count -lt 2) { $results; exit 1 }
$default = (Find-NetRoute -RemoteIPAddress 1.1.1.1 | Select-Object -First 1).InterfaceIndex
$second = $nics | Where-Object InterfaceIndex -ne $default | Select-Object -First 1
$main = $nics | Where-Object InterfaceIndex -eq $default | Select-Object -First 1
$guid = (Get-NetAdapter -InterfaceIndex $second.InterfaceIndex).InterfaceGuid
Write-Host "Основная карта: $($main.InterfaceAlias) $($main.IPAddress); правило → $($second.InterfaceAlias) $($second.IPAddress)"

$udpExe = Join-Path $dir 'ps-udp.exe'
Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $udpExe -Force
$config = Join-Path $dir 'test-config.json'
$rule = { param($app) @{ app = $app; target = @{ type = 'adapter'; id = $guid }; onUnavailable = 'block'; dns = 'adapter'; ipv6 = 'follow'; includeChildren = $true } }
# Приложение из пакета MSIX (#45): winget из App Installer — правило по AUMID, путь к exe служба
# находит по пакету пользователя
$pkgApp = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe!winget'
$hasPkg = [bool](Get-AppxPackage Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue) -and
    [bool](Get-Command winget -ErrorAction SilentlyContinue)
$rules = @((& $rule "$env:SystemRoot\System32\curl.exe"), (& $rule $udpExe))
if ($hasPkg) { $rules += & $rule $pkgApp }
@{ version = 1; primary = 'auto'; rules = $rules } | ConvertTo-Json -Depth 5 | Set-Content $config -Encoding UTF8

function TcpLocalIp { (& "$env:SystemRoot\System32\curl.exe" -s -o NUL -m 15 -w '%{local_ip}' http://example.com/ 2>$null) }
function UdpLocalIp {
    $script = '$u = New-Object Net.Sockets.UdpClient 0; $b=[byte[]](0); [void]$u.Send($b,1,''1.1.1.1'',53); $u.Client.LocalEndPoint.Address.ToString()'
    (& $udpExe -NoProfile -Command $script 2>$null) | Select-Object -Last 1
}
# UDP-сокет без привязки к адресу показывает 0.0.0.0 — смотрим, с какого адреса ушла датаграмма
function UdpSource {
    $script = '$u = New-Object Net.Sockets.UdpClient; $u.Connect(''1.1.1.1'',53); $u.Client.LocalEndPoint.Address.ToString()'
    (& $udpExe -NoProfile -Command $script 2>$null) | Select-Object -Last 1
}

# Фильтры провайдера AppRoute («слой→действие») по выгрузке netsh
function OurFilters {
    $xml = Join-Path $dir 'filters.xml'
    netsh wfp show filters file="$xml" | Out-Null
    [xml]$doc = Get-Content $xml -Raw
    @($doc.SelectNodes('//filters/item') | Where-Object { $_.providerKey -eq '{a8d57f59-f21a-4dea-ab4d-737811dba2dc}' } |
        ForEach-Object { '{0}→{1}' -f ($_.layerKey -replace '^FWPM_LAYER_', ''), $_.action.type })
}

$before = TcpLocalIp
Check 'без правил curl выходит с основной карты' ($before -eq $main.IPAddress) "локальный адрес: $before"

$sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$wfpLog = Join-Path $dir 'wfp-output.txt'
$wfpErr = Join-Path $dir 'wfp-errors.txt'
$serviceLog = Join-Path $env:ProgramData 'AppRoute\routes.log'
Remove-Item $wfpLog, $wfpErr -ErrorAction SilentlyContinue

function CheckRedirected([string]$how) {
    $active = OurFilters
    Check "фильтры AppRoute добавлены ($how)" ($active.Count -gt 0) ($active -join '; ')
    $tcp = TcpLocalIp
    Check 'TCP (curl) — с адреса второй карты' ($tcp -eq $second.IPAddress) "локальный адрес: $tcp"
    $udp = UdpSource
    Check 'UDP (подключённый сокет) — с адреса второй карты' ($udp -eq $second.IPAddress) "локальный адрес: $udp"
    $udpBound = UdpLocalIp
    Check 'UDP (привязка к «любому» адресу) — адрес второй карты' ($udpBound -eq $second.IPAddress) "локальный адрес: $udpBound"
    $other = (Invoke-WebRequest http://example.com/ -UseBasicParsing -TimeoutSec 15).StatusCode
    Check 'другие программы работают как обычно' ($other -eq 200) "PowerShell: $other"
    if ($hasPkg) {
        $pkg = @(PackageLocalIps)
        Check 'приложение из пакета (winget) — с адреса второй карты' ($pkg.Count -gt 0 -and @($pkg | Where-Object { $_ -ne $second.IPAddress }).Count -eq 0) "локальные адреса: $($pkg -join ', ')"
    } else {
        Check 'приложение из пакета (winget)' $true 'пропущено: App Installer не установлен'
    }
}

# Локальные адреса TCP-соединений winget, пока он обновляет источник
function PackageLocalIps {
    $p = Start-Process winget -ArgumentList 'source', 'update', '--disable-interactivity' -PassThru -WindowStyle Hidden
    $ips = @{}
    $deadline = (Get-Date).AddSeconds(60)
    while (-not $p.HasExited -and (Get-Date) -lt $deadline) {
        Get-NetTCPConnection -OwningProcess $p.Id -RemotePort 443, 80 -ErrorAction SilentlyContinue |
            Where-Object LocalAddress -NotIn '0.0.0.0', '::' | ForEach-Object { $ips[$_.LocalAddress] = 1 }
        Start-Sleep -Milliseconds 100
    }
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
    $ips.Keys
}

if ($Service) {
    # --- служба AppRoute с драйвером: правила без отдельного процесса
    & $routes install-service --config $config --client-sid $sid --with-driver
    Check 'служба AppRoute запущена' ((Get-Service AppRoute -ErrorAction SilentlyContinue).Status -eq 'Running')
    Check 'драйвер загружен вместе со службой' ((Get-Service approute-wfp -ErrorAction SilentlyContinue).Status -eq 'Running')
    Start-Sleep 3
    CheckRedirected 'службой'

    # Правка конфига действует на лету: убираем правило curl
    @{ version = 1; primary = 'auto'; rules = @((& $rule $udpExe)) } | ConvertTo-Json -Depth 5 | Set-Content $config -Encoding UTF8
    Start-Sleep 4
    $edited = TcpLocalIp
    Check 'правило curl убрано из конфига — curl с основной карты' ($edited -eq $main.IPAddress) "локальный адрес: $edited"
    $udpStill = UdpSource
    Check 'правило UDP-программы осталось в силе' ($udpStill -eq $second.IPAddress) "локальный адрес: $udpStill"

    # Остановка службы снимает правила
    Stop-Service AppRoute
    Start-Sleep 2
    $left = @(OurFilters).Count
    Check 'служба остановлена — фильтров AppRoute не осталось' ($left -eq 0) "найдено: $left"
    $after = UdpSource
    Check 'после остановки службы UDP-программа с основной карты' ($after -eq $main.IPAddress) "локальный адрес: $after"
} else {
    # --- драйвер и approute-routes wfp
    & $routes install-driver --sys (Join-Path $dir 'approute-wfp.sys')
    Check 'драйвер загружен' ((Get-Service approute-wfp -ErrorAction SilentlyContinue).Status -eq 'Running')
    $wfp = Start-Process $routes -ArgumentList 'wfp', '--config', "`"$config`"", '--client-sid', $sid -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $wfpLog -RedirectStandardError $wfpErr
    Start-Sleep 3
    Check 'approute-routes wfp работает' (-not $wfp.HasExited) $(if ($wfp.HasExited) { "завершился с кодом $($wfp.ExitCode)" })
    CheckRedirected 'approute-routes wfp'

    Stop-Process -Id $wfp.Id -Force
    Start-Sleep 2
    $after = TcpLocalIp
    Check 'после снятия правил curl снова с основной карты' ($after -eq $main.IPAddress) "локальный адрес: $after"
    $left = @(OurFilters).Count
    Check 'фильтров AppRoute не осталось' ($left -eq 0) "найдено: $left"
}

# Счётчики драйвера: он пишет их в раздел своей службы при выгрузке
sc.exe stop approute-wfp | Out-Null
Start-Sleep 2
$stats = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\approute-wfp' -Name Stats -ErrorAction SilentlyContinue).Stats
$statNames = 'вызовов', 'нет права записи', 'нет classifyContext', 'нет контекста провайдера', 'не тот тип',
    'не тот размер', 'не та версия', 'не UDP', 'ошибка доступа', 'подменён', 'не подменён', 'тип', 'размер'
$statsText = if ($stats) {
    $n = 0
    foreach ($callout in 'bind v4', 'bind v6', 'connect v4', 'connect v6') {
        $parts = foreach ($name in $statNames) { '{0}={1}' -f $name, [BitConverter]::ToInt32($stats, $n * 4); $n++ }
        '  {0}: {1}' -f $callout, ($parts -join ', ')
    }
} else { '  (счётчиков нет)' }

if ($Service) {
    $serviceTail = Get-Content $serviceLog -Tail 25 -Encoding UTF8 -ErrorAction SilentlyContinue
    & $routes uninstall-service
    Check 'служба AppRoute удалена' (-not (Get-Service AppRoute -ErrorAction SilentlyContinue))
    Check 'драйвер удалён вместе со службой' (-not (Get-Service approute-wfp -ErrorAction SilentlyContinue))
    $installed = Join-Path $env:ProgramFiles 'AppRoute\approute-wfp.sys'
    Check 'файл драйвера удалён' (-not (Test-Path $installed))
} else {
    & $routes uninstall-driver
    Check 'драйвер выгружен' (-not (Get-Service approute-wfp -ErrorAction SilentlyContinue))
}

Write-Host ''
Write-Host '=== Итог (скопируйте в чат) ==='
$results
'--- счётчики драйвера ---'
$statsText
if ($Service) {
    # install-service / uninstall-service пишут итог не в консоль, а в install.log (его читает окно)
    '--- журнал установки (конец) ---'
    Get-Content (Join-Path $env:ProgramData 'AppRoute\install.log') -Tail 6 -Encoding UTF8 -ErrorAction SilentlyContinue
    '--- журнал службы (конец) ---'
    $serviceTail
} else {
    '--- вывод approute-routes wfp ---'
    Get-Content $wfpLog, $wfpErr -Encoding UTF8 -ErrorAction SilentlyContinue
}
