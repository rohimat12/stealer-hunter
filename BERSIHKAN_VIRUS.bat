@echo off
setlocal enabledelayedexpansion
title StealerHunter - Emergency Infostealer First-Aid
color 0A

:: ----------------------------------------------------
:: 0. Verifikasi Hak Administrator (Auto-Elevate)
:: ----------------------------------------------------
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ===================================================
    echo  MEMERLUKAN HAK AKSES ADMINISTRATOR
    echo  Klik kanan file ini lalu pilih 'Run as administrator'
    echo ===================================================
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process '%~f0' -Verb RunAs" >nul 2>&1
    exit /b
)

echo ========================================================
echo   STEALERHUNTER - EMERGENCY FIRST-AID RESPONSE TOOLKIT
echo   Pembersihan Cepat Infostealer, Dropper, & Autorun
echo ========================================================
echo.

set "QUARANTINE_DIR=%APPDATA%\StealerHunter\Quarantine"
if not exist "%QUARANTINE_DIR%" mkdir "%QUARANTINE_DIR%" >nul 2>&1

:: ----------------------------------------------------
:: 1. Mematikan Proses Malware Aktif & Masquerading
:: ----------------------------------------------------
echo [1/5] Memindai dan mematikan proses asing / stealer aktif...

:: Matikan nama proses yang diketahui dari infeksi nyata
for %%P in (
    "icsys.icn.exe"
    "icsys.exe"
    "mofk.exe"
    "stealc.exe"
    "lumma.exe"
    "redline.exe"
) do (
    taskkill /F /IM "%%~P" >nul 2>&1
    if !errorlevel! equ 0 echo   [TERDETEKSI] Proses jahat dihentikan: %%~P
)

:: Deteksi via PowerShell: cari proses dari folder mencurigakan (Themes, Temp, Roaming root)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$riskyPaths = @('C:\Windows\Resources', $env:TEMP, (Join-Path $env:APPDATA '..\Local\Temp'));" ^
    "Get-Process -ErrorAction SilentlyContinue | Where-Object {" ^
    "    $path = try { $_.MainModule.FileName } catch { $null };" ^
    "    if ($path) {" ^
    "        foreach ($rp in $riskyPaths) {" ^
    "            if ($path.StartsWith($rp, [System.StringComparison]::OrdinalIgnoreCase) -and $_.ProcessName -notmatch '^(devenv|dotnet|code)$') {" ^
    "                Write-Host '  [KILL] Mematikan proses mencurigakan:' $_.ProcessName '(' $path ')';" ^
    "                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue;" ^
    "                break;" ^
    "            }" ^
    "        }" ^
    "    }" ^
    "}"
echo   [OK] Pemeriksaan memori proses selesai.

:: ----------------------------------------------------
:: 2. Menyapu Bersih Berkas Biner Terlarang di Windows Themes
:: ----------------------------------------------------
echo.
echo [2/5] Memeriksa folder tema sistem (C:\Windows\Resources\Themes)...
:: Folder Themes resmi Windows hanya berisi .theme dan .msstyles, TIDAK BOLEH ada .exe/.scr/.bat/.vbs
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$targetDir = 'C:\Windows\Resources\Themes';" ^
    "$qDir = '%QUARANTINE_DIR%';" ^
    "if (Test-Path $targetDir) {" ^
    "    $badFiles = Get-ChildItem -Path $targetDir -Recurse -File -Include *.exe,*.scr,*.bat,*.cmd,*.vbs,*.ps1,*.icn -ErrorAction SilentlyContinue;" ^
    "    if ($badFiles.Count -eq 0) { Write-Host '  [BERSIH] Tidak ada file eksekutabel ilegal di folder Themes.'; }" ^
    "    foreach ($f in $badFiles) {" ^
    "        try {" ^
    "            $dest = Join-Path $qDir ($f.Name + '_' + (Get-Date -Format 'yyyyMMddHHmmss') + '.quarantined');" ^
    "            $bytes = [System.IO.File]::ReadAllBytes($f.FullName);" ^
    "            for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor 0x5A };" ^
    "            [System.IO.File]::WriteAllBytes($dest, $bytes);" ^
    "            Remove-Item -Path $f.FullName -Force;" ^
    "            Write-Host '  [KARANTINA] Berkas ilegal disamarkan & dipindahkan:' $f.Name '-> Quarantine';" ^
    "        } catch {" ^
    "            Write-Host '  [GAGAL] Tidak bisa memindahkan:' $f.FullName $_.Exception.Message;" ^
    "        }" ^
    "    }" ^
    "}"

:: ----------------------------------------------------
:: 3. Membersihkan Entri Registry Autorun Siluman
:: ----------------------------------------------------
echo.
echo [3/5] Memeriksa dan membersihkan entri Registry Autorun...

:: Pembersihan HKLM WOW6432Node
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Explorer" /f >nul 2>&1
if %errorlevel% equ 0 echo   [OK] Hapus Run HKLM\WOW6432Node: 'Explorer' (Palsu)
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Svchost" /f >nul 2>&1
if %errorlevel% equ 0 echo   [OK] Hapus Run HKLM\WOW6432Node: 'Svchost' (Palsu)

:: Pembersihan HKLM Standard
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Explorer" /f >nul 2>&1
if %errorlevel% equ 0 echo   [OK] Hapus Run HKLM: 'Explorer' (Palsu)
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Svchost" /f >nul 2>&1
if %errorlevel% equ 0 echo   [OK] Hapus Run HKLM: 'Svchost' (Palsu)

:: Pembersihan HKCU (Current User) Run & RunOnce mencurigakan
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$keys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce');" ^
    "foreach ($k in $keys) {" ^
    "    if (Test-Path $k) {" ^
    "        $props = (Get-Item $k).Property;" ^
    "        foreach ($p in $props) {" ^
    "            $val = (Get-ItemProperty -Path $k -Name $p).$p;" ^
    "            if ($val -match '(?i)(Resources\\Themes|Temp\\|icsys|mofk|powershell.*-enc|wscript.*\.vbs)') {" ^
    "                Remove-ItemProperty -Path $k -Name $p -Force -ErrorAction SilentlyContinue;" ^
    "                Write-Host '  [TERHAPUS] Registry Run Jahat:' $p '->' $val;" ^
    "            }" ^
    "        }" ^
    "    }" ^
    "}"
echo   [OK] Pembersihan entri autorun selesai.

:: ----------------------------------------------------
:: 4. Membersihkan Staging Exfiltration & Dump Curian di %TEMP%
:: ----------------------------------------------------
echo.
echo [4/5] Menyapu sampah staging eksfiltrasi stealer di %%TEMP%%...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$tempDirs = @($env:TEMP, (Join-Path $env:APPDATA '..\Local\Temp'));" ^
    "$count = 0;" ^
    "foreach ($td in $tempDirs) {" ^
    "    if (Test-Path $td) {" ^
    "        $dumps = Get-ChildItem -Path $td -File -ErrorAction SilentlyContinue | Where-Object {" ^
    "            $_.Name -match '(?i)^(passwords?\.txt|cookies?\.txt|autofill\.txt|wallets?|cards?\.txt|all_cookies\.txt)$' -or " ^
    "            ($_.Name -match '(?i)^[a-f0-9]{16,32}\.zip$')" ^
    "        };" ^
    "        foreach ($d in $dumps) {" ^
    "            Remove-Item -Path $d.FullName -Force -ErrorAction SilentlyContinue;" ^
    "            Write-Host '  [BERSIH] Sampah eksfiltrasi dihapus:' $d.Name;" ^
    "            $count++;" ^
    "        }" ^
    "    }" ^
    "};" ^
    "if ($count -eq 0) { Write-Host '  [BERSIH] Tidak ditemukan file dump eksfiltrasi aktif di Temp.'; }"

:: ----------------------------------------------------
:: 5. Pemeriksaan Kredensial Browser & Peluncuran StealerHunter
:: ----------------------------------------------------
echo.
echo [5/5] Memeriksa ketersediaan aplikasi StealerHunter GUI...

set "SH_EXE="
if exist "%~dp0StealerHunter\bin\Release\net8.0-windows\win-x64\StealerHunter.exe" set "SH_EXE=%~dp0StealerHunter\bin\Release\net8.0-windows\win-x64\StealerHunter.exe"
if not defined SH_EXE if exist "%~dp0StealerHunter\publish\win-x64\StealerHunter.exe" set "SH_EXE=%~dp0StealerHunter\publish\win-x64\StealerHunter.exe"
if not defined SH_EXE if exist "%ProgramFiles%\StealerHunter\StealerHunter.exe" set "SH_EXE=%ProgramFiles%\StealerHunter\StealerHunter.exe"
if not defined SH_EXE if exist "%LOCALAPPDATA%\Programs\StealerHunter\StealerHunter.exe" set "SH_EXE=%LOCALAPPDATA%\Programs\StealerHunter\StealerHunter.exe"

echo.
echo ========================================================
echo   PEMBERSIHAN TAHAP PERTOLONGAN PERTAMA SELESAI!
echo   Semua file jahat yang ditemukan telah diamankan di:
echo   %QUARANTINE_DIR%
echo ========================================================
echo.

if defined SH_EXE (
    echo [REKOMENDASI] StealerHunter GUI terdeteksi di komputer ini.
    echo Disarankan menjalankan Deep Scan untuk audit integritas browser
    echo dan mencocokkan hash dengan 1.230+ database Abuse.ch.
    echo.
    set /p RUN_SH="Buka StealerHunter sekarang? (Y/N): "
    if /i "!RUN_SH!"=="Y" (
        echo Membuka StealerHunter...
        start "" "%SH_EXE%"
    )
) else (
    echo [INFO] Untuk pemindaian menyeluruh terhadap 1.230+ signature Abuse.ch
    echo dan Master File Table (MFT), silakan jalankan StealerHunter GUI.
)

echo.
echo Selesai. Tekan tombol apa saja untuk menutup jendela ini...
pause >nul
