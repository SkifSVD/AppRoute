<#
    Собирает resources/approute.ico из resources/baseIco.jpg: белый фон становится прозрачным,
    линии — сплошным цветом с альфа-каналом по яркости (сглаживание сохраняется).
    Размеры 16–256 px, каждый кадр — PNG внутри ICO (поддерживается с Windows Vista).
    Пример: ./resources/make-icon.ps1
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$src = Join-Path $PSScriptRoot 'baseIco.jpg'
$dst = Join-Path $PSScriptRoot 'approute.ico'
$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256

$source = [System.Drawing.Bitmap]::new($src)

# Цвет линий — средний цвет их «сердцевины» (насыщенные пиксели), без артефактов JPEG по краям
[long]$sr = 0; [long]$sg = 0; [long]$sb = 0; [long]$n = 0
for ($y = 0; $y -lt $source.Height; $y += 2) {
    for ($x = 0; $x -lt $source.Width; $x += 2) {
        $p = $source.GetPixel($x, $y)
        if ($p.R -lt 60 -and $p.B -gt 150) { $sr += $p.R; $sg += $p.G; $sb += $p.B; $n++ }
    }
}
if ($n -eq 0) { throw 'не найден цвет линий' }
$ink = [System.Drawing.Color]::FromArgb([int]($sr / $n), [int]($sg / $n), [int]($sb / $n))

# Прозрачный вариант в исходном размере: альфа по «небелизне» относительно цвета линий
$alpha = [System.Drawing.Bitmap]::new($source.Width, $source.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$range = [Math]::Max(1, 255 - [Math]::Min($ink.R, [Math]::Min($ink.G, $ink.B)))
for ($y = 0; $y -lt $source.Height; $y++) {
    for ($x = 0; $x -lt $source.Width; $x++) {
        $p = $source.GetPixel($x, $y)
        $m = [Math]::Min($p.R, [Math]::Min($p.G, $p.B))
        $a = [int][Math]::Round([Math]::Min(255, [Math]::Max(0, (255 - $m) * 255 / $range)))
        $alpha.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($a, $ink.R, $ink.G, $ink.B))
    }
}
$source.Dispose()

$frames = foreach ($s in $sizes) {
    $bmp = [System.Drawing.Bitmap]::new($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
    $g.DrawImage($alpha, 0, 0, $s, $s)
    $g.Dispose()
    $ms = [System.IO.MemoryStream]::new()
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    [pscustomobject]@{ Size = $s; Data = $ms.ToArray() }
}
$alpha.Dispose()

# ICONDIR + ICONDIRENTRY[] + PNG-данные
$out = [System.IO.MemoryStream]::new()
$w = [System.IO.BinaryWriter]::new($out)
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$frames.Count)
$offset = 6 + 16 * $frames.Count
foreach ($f in $frames) {
    $dim = if ($f.Size -ge 256) { 0 } else { $f.Size }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$f.Data.Length); $w.Write([uint32]$offset)
    $offset += $f.Data.Length
}
foreach ($f in $frames) { $w.Write($f.Data) }
$w.Flush()
[System.IO.File]::WriteAllBytes($dst, $out.ToArray())
"$dst — $($frames.Count) размеров, $([int]($out.Length / 1KB)) КБ, цвет линий #{0:X2}{1:X2}{2:X2}" -f $ink.R, $ink.G, $ink.B
