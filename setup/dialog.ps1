Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Светлая тема — белое окно в стиле программы
$light = $true
function C($hex) { [System.Drawing.ColorTranslator]::FromHtml($hex) }
if ($light) { $BG = C '#fafafa'; $FG = C '#0a0a0a'; $MUT = C '#6b6b6b'; $LINE = C '#e0e0e0'; $RAISE = C '#f0f0f0' }
else        { $BG = C '#0a0a0a'; $FG = C '#f2f2f2'; $MUT = C '#8c8c8c'; $LINE = C '#262626'; $RAISE = C '#141414' }
$fSans  = New-Object System.Drawing.Font('Segoe UI', 9.5)
$fCaps  = New-Object System.Drawing.Font('Segoe UI Semibold', 8)
$fBig   = New-Object System.Drawing.Font('Segoe UI', 22, [System.Drawing.FontStyle]::Bold)
$fMono  = New-Object System.Drawing.Font('Consolas', 9)
function Spaced($s, [switch]$Keep) { $t = if ($Keep) { $s } else { $s.ToUpper() }; ($t.ToCharArray() -join [char]0x200A) }  # разрядка, как в интерфейсе

$W = 540; $H = 470
$f = New-Object System.Windows.Forms.Form
$f.Text = 'Установка NETtool ' + $env:VA_VER
$f.FormBorderStyle = 'None'; $f.ClientSize = New-Object System.Drawing.Size($W, $H)
$f.StartPosition = 'CenterScreen'; $f.TopMost = $true; $f.ShowInTaskbar = $true
$f.BackColor = $BG; $f.ForeColor = $FG; $f.Font = $fSans
try { $f.Icon = New-Object System.Drawing.Icon($env:VA_ICO) } catch {}
$f.Add_Paint({ $p = New-Object System.Drawing.Pen($LINE, 1); $_.Graphics.DrawRectangle($p, 0, 0, $f.ClientSize.Width - 1, $f.ClientSize.Height - 1); $p.Dispose() })

function Lbl($text, $x, $y, $font, $color) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text; $l.AutoSize = $true; $l.Location = New-Object System.Drawing.Point($x, $y)
    $l.Font = $font; $l.ForeColor = $color; $l.BackColor = [System.Drawing.Color]::Transparent
    $f.Controls.Add($l); $l
}
function Line($y) {
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = New-Object System.Drawing.Point(24, $y); $p.Size = New-Object System.Drawing.Size(($W - 48), 1); $p.BackColor = $LINE
    $f.Controls.Add($p); $p
}

# --- своя полоса заголовка: перетаскивание и закрытие ---
$bar = New-Object System.Windows.Forms.Panel
$bar.Location = New-Object System.Drawing.Point(1, 1); $bar.Size = New-Object System.Drawing.Size(($W - 2), 30); $bar.BackColor = $BG
$f.Controls.Add($bar)
$barT = New-Object System.Windows.Forms.Label
$barT.Text = (Spaced 'Установка'); $barT.Font = $fCaps; $barT.ForeColor = $MUT; $barT.AutoSize = $true
$barT.Location = New-Object System.Drawing.Point(23, 9); $bar.Controls.Add($barT)
$x = New-Object System.Windows.Forms.Label
$x.Text = '×'; $x.Font = New-Object System.Drawing.Font('Consolas', 12); $x.ForeColor = $MUT; $x.TextAlign = 'MiddleCenter'
$x.Size = New-Object System.Drawing.Size(46, 30); $x.Location = New-Object System.Drawing.Point(($W - 48), 0); $x.Cursor = 'Hand'
$x.Add_MouseEnter({ $x.BackColor = $FG; $x.ForeColor = $BG }); $x.Add_MouseLeave({ $x.BackColor = $BG; $x.ForeColor = $MUT })
$x.Add_Click({ $f.Close() }); $bar.Controls.Add($x)
$script:drag = $null
$down = { if ($_.Button -eq 'Left') { $script:drag = [System.Windows.Forms.Cursor]::Position; $script:at = $f.Location } }
$move = { if ($script:drag -and [System.Windows.Forms.Control]::MouseButtons -eq 'Left') {
    $c = [System.Windows.Forms.Cursor]::Position
    $f.Location = New-Object System.Drawing.Point(($script:at.X + $c.X - $script:drag.X), ($script:at.Y + $c.Y - $script:drag.Y)) } }
$up = { $script:drag = $null }
foreach ($c in @($bar, $barT)) { $c.Add_MouseDown($down); $c.Add_MouseMove($move); $c.Add_MouseUp($up) }

# --- шапка ---
[void](Lbl (Spaced 'NETtool' -Keep) 24 48 $fCaps $FG)
[void](Lbl ('v' + $env:VA_VER + ' · undr') ($W - 130) 48 $fMono $MUT)
$hdr = Line 70; $hdr.BackColor = $FG; $hdr.Height = 2
[void](Lbl $env:VA_BTN.ToUpper() 20 84 $fBig $FG)
[void](Lbl $env:VA_MODE 24 128 $fSans $MUT)

# --- папка ---
[void](Lbl (Spaced 'Папка') 24 166 $fCaps $MUT)
$tb = New-Object System.Windows.Forms.TextBox
$tb.Text = $env:VA_DIR; $tb.Location = New-Object System.Drawing.Point(24, 186); $tb.Size = New-Object System.Drawing.Size(($W - 48 - 100), 24)
$tb.BorderStyle = 'FixedSingle'; $tb.BackColor = $RAISE; $tb.ForeColor = $FG; $tb.Font = $fMono
$f.Controls.Add($tb)

function Btn($text, $x, $y, $w, $primary) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.Location = New-Object System.Drawing.Point($x, $y); $b.Size = New-Object System.Drawing.Size($w, 32)
    $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 1; $b.FlatAppearance.BorderColor = $FG; $b.Font = $fCaps; $b.Cursor = 'Hand'
    if ($primary) { $b.BackColor = $FG; $b.ForeColor = $BG; $b.FlatAppearance.MouseOverBackColor = $MUT; $b.FlatAppearance.MouseDownBackColor = $MUT }
    else { $b.BackColor = $BG; $b.ForeColor = $FG; $b.FlatAppearance.MouseOverBackColor = $RAISE; $b.FlatAppearance.MouseDownBackColor = $LINE }
    $f.Controls.Add($b); $b
}
$br = Btn (Spaced 'Обзор') ($W - 24 - 92) 185 92 $false
$br.Height = 26
$br.Add_Click({
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    $d.Description = 'Выберите папку — внутри неё будет создана папка «NETtool»'
    $parent = Split-Path $tb.Text -Parent
    if ($parent -and (Test-Path $parent)) { $d.SelectedPath = $parent }
    if ($d.ShowDialog($f) -eq 'OK') {
        $p = $d.SelectedPath
        $leaf = Split-Path $p -Leaf; if ($leaf -ne 'NETtool' -and $leaf -ne 'VPN Auto') { $p = Join-Path $p 'NETtool' }
        $tb.Text = $p
    }
})

# --- квадратные переключатели, как в программе ---
[void](Lbl (Spaced 'Параметры') 24 228 $fCaps $MUT)
$script:checks = @{}
function Check($key, $text, $y, $on) {
    $l = New-Object System.Windows.Forms.Label
    $l.AutoSize = $false; $l.Size = New-Object System.Drawing.Size(($W - 48), 26); $l.Location = New-Object System.Drawing.Point(24, $y)
    $l.Font = $fSans; $l.ForeColor = $FG; $l.Cursor = 'Hand'; $l.TextAlign = 'MiddleLeft'; $l.Tag = $key
    $f.Controls.Add($l)
    $script:checks[$key] = @{ L = $l; On = [bool]$on; T = $text }
    Draw $key
    $l.Add_Click({ Toggle $this.Tag })
    $l.Add_MouseEnter({ $this.BackColor = $RAISE }); $l.Add_MouseLeave({ $this.BackColor = $BG })
}
function Draw($key) { $c = $script:checks[$key]; $c.L.Text = ($(if ($c.On) { '■' } else { '□' })) + '   ' + $c.T }
function SetC($key, $v) { $script:checks[$key].On = [bool]$v; Draw $key }
function Toggle($key) {
    $v = -not $script:checks[$key].On; SetC $key $v
    if ($key -eq 'warp' -and $v) { SetC 'zap' $true }       # WARP работает через запрет
    if ($key -eq 'zap' -and -not $v) { SetC 'warp' $false }
}
Check 'desk' 'Ярлык на рабочем столе' 248 ($env:VA_DESK -eq '1')
Check 'run'  'Запустить после установки' 274 $true
Check 'auto' 'Запускать с Windows — сразу включается запрет (без WARP)' 300 $true
Check 'zap'  'Запрет (Zapret) — обход блокировок без VPN' 326 ($env:VA_ZAP -eq '1')
Check 'warp' 'Cloudflare WARP — скачается ~130 МБ, будет обновляться' 352 ($env:VA_WARP -eq '1')
Check 'tg'   'TG WS Proxy — ускорение Telegram' 378 ($env:VA_TG -eq '1')

[void](Line 418)
$ok = Btn (Spaced $env:VA_BTN) ($W - 24 - 140 - 10 - 100) 428 140 $true
$cancel = Btn (Spaced 'Отмена') ($W - 24 - 100) 428 100 $false
$ok.Add_Click({
    if (-not $tb.Text.Trim()) { return }
    $k = $script:checks
    $lines = @($tb.Text.Trim(), [int]$k.desk.On, [int]$k.run.On, [int]$k.zap.On, [int]$k.warp.On, [int]$k.tg.On, [int]$k.auto.On)
    [IO.File]::WriteAllLines($env:VA_OUT, [string[]]$lines, (New-Object Text.UTF8Encoding $false))
    $f.Close()
})
$cancel.Add_Click({ $f.Close() })
$f.AcceptButton = $ok; $f.CancelButton = $cancel
$f.Add_Shown({ $f.Activate(); $ok.Focus() })
[void]$f.ShowDialog()
