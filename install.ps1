# VPNCheck Stand - установка на Windows / Windows installer.
#
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Ставит (если их нет) Python 3.12, adb и scrcpy через winget, зависимости Python,
# скачивает ядро xray для телефонов (tools/fetch_binaries.py) и кладёт ярлык на рабочий стол.
# Можно запускать повторно - уже установленное пропускается.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Say($ru, $en) { Write-Host ("* {0} / {1}" -f $ru, $en) -ForegroundColor Cyan }

function Find-Python {
    # py -3 (лаунчер python.org) или python из PATH; нужен 3.10+
    $candidates = @(@{Exe = "py"; Args = @("-3")}, @{Exe = "python"; Args = @()},
        @{Exe = (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"); Args = @()},
        @{Exe = (Join-Path $env:ProgramFiles "Python312\python.exe"); Args = @()})
    foreach ($try in $candidates) {
        if ($null -eq (Get-Command $try.Exe -ErrorAction SilentlyContinue)) { continue }
        $a = $try.Args
        try { $ver = & $try.Exe @a -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null } catch { continue }
        if ($ver -and [version]$ver -ge [version]"3.10") { return [pscustomobject]$try }
    }
    return $null
}

function Has-Winget { return $null -ne (Get-Command winget -ErrorAction SilentlyContinue) }

function Winget-Install($id) {
    if (-not (Has-Winget)) { throw "winget не найден - поставьте $id вручную / winget not found: install $id manually" }
    winget install --id $id -e --silent --accept-source-agreements --accept-package-agreements | Out-Host
}

# 1. Python
$py = Find-Python
if ($null -eq $py) {
    Say "Ставлю Python 3.12" "Installing Python 3.12"
    Winget-Install "Python.Python.3.12"
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
    $py = Find-Python
    if ($null -eq $py) { throw "Python не появился в PATH - откройте новое окно PowerShell и запустите install.ps1 ещё раз / reopen PowerShell and run again" }
}
$pyExe = $py.Exe
$pyArgs = $py.Args
Say "Python: $(& $pyExe @pyArgs --version)" "Python found"
$pythonw = & $pyExe @pyArgs -c "import os, sys; print(os.path.join(os.path.dirname(sys.executable), 'pythonw.exe'))"

# 2. Зависимости Python / Python packages
Say "Ставлю зависимости (PySide6, paramiko, segno, cryptography)" "Installing Python packages"
& $pyExe @pyArgs -m pip install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install не прошёл - см. сообщения выше и README, «Частые проблемы» (длинные пути) / pip install failed - see the messages above and README, Troubleshooting (long paths)" }

# 3. adb и scrcpy / adb and scrcpy
if ($null -eq (Get-Command adb -ErrorAction SilentlyContinue)) {
    Say "Ставлю adb (Google Platform Tools)" "Installing adb"
    Winget-Install "Google.PlatformTools"
} else { Say "adb уже есть" "adb already installed" }
if ($null -eq (Get-Command scrcpy -ErrorAction SilentlyContinue)) {
    Say "Ставлю scrcpy (экран телефона в окне, по желанию)" "Installing scrcpy (optional phone screen)"
    try { Winget-Install "Genymobile.scrcpy" } catch { Write-Warning "scrcpy не поставился - программа работает и без него / scrcpy is optional" }
}

# 4. Ядро xray для телефонов / xray core for phones
$xrayWant = & $pyExe @pyArgs -c "import sys; sys.path.insert(0, '.'); from stand.dcprobe import XRAY_VERSION; print(XRAY_VERSION)"
if ($LASTEXITCODE -ne 0 -or -not $xrayWant) { throw "не удалось прочитать XRAY_VERSION из stand\dcprobe.py / could not read XRAY_VERSION from stand\dcprobe.py" }
$xrayWant = "$xrayWant".Trim()
$xrayHave = ""
if (Test-Path "bin\xray.version") { $xrayHave = (Get-Content "bin\xray.version" -Raw).Trim() }
if (-not (Test-Path "bin\xray") -or $xrayHave -ne $xrayWant) {
    Say "Скачиваю xray $xrayWant (официальный релиз, сверка SHA-256)" "Downloading xray $xrayWant (official release, SHA-256 checked)"
    & $pyExe @pyArgs tools\fetch_binaries.py
    if ($LASTEXITCODE -ne 0) { throw "не удалось скачать ядро Xray (fetch_binaries.py) - проверьте интернет и запустите ещё раз / fetch_binaries.py failed - check the internet connection and run again" }
} else { Say "bin\xray $xrayHave уже есть" "bin\xray $xrayHave already present" }

# 5. Ярлык / Desktop shortcut
$desktop = [Environment]::GetFolderPath("Desktop")
$link = Join-Path $desktop "VPNCheck Stand.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($link)
if ($pythonw -and (Test-Path $pythonw)) {
    $shortcut.TargetPath = $pythonw
    $shortcut.Arguments = '"' + (Join-Path $PSScriptRoot "app.py") + '"'
} else {
    $shortcut.TargetPath = Join-Path $PSScriptRoot "VPNCheck Stand.bat"
    $shortcut.Arguments = ""
}
$shortcut.WorkingDirectory = $PSScriptRoot
$shortcut.IconLocation = Join-Path $PSScriptRoot "stand\ui\assets\icon.ico"
$shortcut.WindowStyle = 7
$shortcut.Save()
Say "Ярлык на рабочем столе: VPNCheck Stand" "Desktop shortcut created"

Write-Host ""
Write-Host "Готово. Включите на телефоне «Отладка по USB», подключите кабелем и запустите ярлык." -ForegroundColor Green
Write-Host "Done. Enable USB debugging on the phone, plug it in and start the shortcut." -ForegroundColor Green
