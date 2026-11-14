#Requires -Version 7
<#
.SYNOPSIS
    Храповик размера файлов: новые файлы — не больше лимита, большие — только уменьшаются.

.DESCRIPTION
    Проверяет объём исходников (`src/`, `tests/`) по базовой линии `tools/size-baseline.json`
    (правило — в docs/conventions.md).

    Файл не больше лимита своей группы — свободен, в базовой линии его быть не должно.
    Файл больше лимита — записан в базовую линию с потолком, равным текущему размеру:

      * вырос выше потолка — ошибка: сначала вынесите часть в отдельный файл;
      * уменьшился — ошибка: затяните храповик ключом -Write;
      * совпал с потолком — норма.

    -Write только опускает потолки. Поднять их скрипт не может: если файл вырос, -Write пишет
    прежний потолок и завершается ошибкой. Новый файл больше лимита -Write не принимает — его
    нужно разделить. Обойти это можно только правкой JSON в отдельном PR, и это видно в диффе.

.PARAMETER Write
    Затянуть храповик: опустить потолки до текущих размеров, убрать записи файлов, которые уже
    под лимитом или удалены.

.PARAMETER Report
    Только показать самые большие файлы и их потолки, ничего не проверять.

.EXAMPLE
    ./tools/Size-Ratchet.ps1

.EXAMPLE
    ./tools/Size-Ratchet.ps1 -Write    # после того, как вынесли часть большого файла

.EXAMPLE
    ./tools/Size-Ratchet.ps1 -Report
#>
param(
    [switch]$Write,
    [switch]$Report,
    [string]$Baseline = (Join-Path $PSScriptRoot 'size-baseline.json'),
    [string]$Root = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'

$extensions = @('.cpp', '.h', '.c', '.hpp')

if (-not (Test-Path $Baseline)) { throw "Нет базовой линии: $Baseline" }

$data = Get-Content $Baseline -Raw -Encoding utf8 | ConvertFrom-Json
$limit = [int]$data.maxLines
$paths = @($data.paths)
$ceilings = @{}
if ($data.files) {
    foreach ($p in $data.files.PSObject.Properties) { $ceilings[$p.Name] = [int]$p.Value }
}

# Текущие размеры: перебираем только объявленные пути, чтобы область была явной
$sizes = @{}
foreach ($path in $paths) {
    $dir = Join-Path $Root $path
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem $dir -Recurse -File |
        Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() } |
        ForEach-Object {
            $rel = [System.IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\', '/')
            $sizes[$rel] = [int](Get-Content $_.FullName | Measure-Object -Line).Lines
        }
}

$ordered = $sizes.Keys | Sort-Object

if ($Report) {
    $ordered |
        ForEach-Object { [pscustomobject]@{ Строк = $sizes[$_]; Потолок = $ceilings[$_]; Лимит = $limit; Файл = $_ } } |
        Sort-Object Строк -Descending |
        Select-Object -First 25 |
        Format-Table -AutoSize
    '{0} файлов, {1} в базовой линии' -f $sizes.Count, $ceilings.Count
    exit 0
}

# Блокирующие — их не исправить затягиванием храповика: файл вырос или новый файл выше лимита.
# Исправимые — устаревшие записи: файл уменьшился, ушёл под лимит или удалён.
$blocking = [System.Collections.Generic.List[string]]::new()
$fixable = [System.Collections.Generic.List[string]]::new()
$next = [ordered]@{}

foreach ($rel in $ordered) {
    $lines = $sizes[$rel]
    $ceiling = $ceilings[$rel]

    if ($lines -le $limit) {
        if ($null -ne $ceiling) {
            $fixable.Add("$rel`: $lines строк — уже не больше лимита $limit, запись в базовой линии лишняя")
        }
        continue
    }

    if ($null -eq $ceiling) {
        $blocking.Add("$rel`: $lines строк при лимите $limit — файл выше лимита и не в базовой линии; разделите его")
        continue
    }

    if ($lines -gt $ceiling) {
        $blocking.Add("$rel`: $lines строк, потолок $ceiling — файл вырос; сначала вынесите часть в отдельный файл")
        $next[$rel] = $ceiling
        continue
    }

    if ($lines -lt $ceiling) {
        $fixable.Add("$rel`: $lines строк, потолок $ceiling — файл уменьшился; потолок опускается ключом -Write")
    }
    $next[$rel] = $lines
}

# Записи для удалённых файлов
foreach ($rel in ($ceilings.Keys | Sort-Object)) {
    if (-not $sizes.ContainsKey($rel)) { $fixable.Add("$rel`: запись в базовой линии есть, файла нет") }
}

if ($Write) {
    $out = [ordered]@{
        version  = 1
        note     = 'Потолок храповика (docs/conventions.md). Поднимать вручную нельзя: только -Write, и только вниз.'
        maxLines = $limit
        paths    = @($paths)
        files    = $next
    }
    $json = $out | ConvertTo-Json -Depth 4
    Set-Content -Path $Baseline -Value $json -Encoding utf8NoBOM
    Write-Host "Базовая линия обновлена: $Baseline ($($next.Count) файлов)" -ForegroundColor Green
    foreach ($p in $fixable) { Write-Host "  ✓ $p" -ForegroundColor DarkGray }
    $fixable.Clear()
}

$problems = @($blocking) + @($fixable)
if ($problems.Count -gt 0) {
    Write-Host ''
    foreach ($p in $problems) { Write-Host "  ✗ $p" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host "Правило: docs/conventions.md, раздел «Храповик размера файлов»." -ForegroundColor Cyan
    exit 1
}

Write-Host "Храповик в порядке: $($sizes.Count) файлов, $($next.Count) с потолком." -ForegroundColor Green
exit 0
