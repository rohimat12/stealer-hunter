<# :
@echo off
setlocal
title StealerHunter - Emergency Infostealer First-Aid
color 0A

:: 1. Verifikasi Hak Administrator (Auto-Elevate)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ===================================================
    echo  MEMERLUKAN HAK AKSES ADMINISTRATOR
    echo  Sedang meminta izin Administrator...
    echo ===================================================
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: 2. Jalankan Logika Pembersihan Menggunakan PowerShell Bawaan
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText('%~f0'))"

echo.
echo ========================================================
echo  Jendela ini tidak akan tertutup otomatis.
echo  Tekan tombol apa saja untuk keluar...
echo ========================================================
pause >nul
exit /b
: #>

# ==========================================================
# STEALERHUNTER - EMERGENCY FIRST-AID RESPONSE POWERSHELL
# ==========================================================
$Host.UI.RawUI.WindowTitle = "StealerHunter - Emergency First-Aid Toolkit"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  STEALERHUNTER - EMERGENCY FIRST-AID RESPONSE TOOLKIT  " -ForegroundColor Green
Write-Host "  Pembersihan Cepat Infostealer, Dropper, & Autorun     " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$quarantineDir = Join-Path $env:APPDATA "StealerHunter\Quarantine"
if (-not (Test-Path $quarantineDir)) {
    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
}

# ----------------------------------------------------------
# 1. PENGHENTIAN PROSES MALWARE AKTIF
# ----------------------------------------------------------
Write-Host "[1/5] Memindai dan mematikan proses malware aktif..." -ForegroundColor Yellow

$knownBad = @("icsys.icn.exe", "icsys.exe", "mofk.exe", "stealc.exe", "lumma.exe", "redline.exe", "vidar.exe", "spoolsv.exe")
$killedCount = 0

foreach ($bad in $knownBad) {
    $procs = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($bad)) -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        try {
            $pPath = $p.MainModule.FileName
            # Hindari mematikan spoolsv resmi Windows di System32
            if ($p.ProcessName -eq "spoolsv" -and $pPath -like "*\System32\*") { continue }
            
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            Write-Host "  [TERDETEKSI] Proses dihentikan: $($p.ProcessName) ($pPath)" -ForegroundColor Red
            $killedCount++
        } catch { }
    }
}

# Deteksi proses yang berjalan dari folder mencurigakan (Themes, Temp)
$riskyPrefixes = @("C:\Windows\Resources", $env:TEMP, (Join-Path $env:LOCALAPPDATA "Temp"))
$allProcs = Get-Process -ErrorAction SilentlyContinue
foreach ($p in $allProcs) {
    try {
        $filePath = $p.MainModule.FileName
        if ($filePath) {
            foreach ($rp in $riskyPrefixes) {
                if ($filePath.StartsWith($rp, [System.StringComparison]::OrdinalIgnoreCase)) {
                    # Whitelist developer/system tools jika ada
                    if ($p.ProcessName -match '^(devenv|dotnet|code|pwsh|powershell|cmd)$') { continue }
                    
                    Write-Host "  [TERDETEKSI] Mematikan proses asing dari lokasi berisiko:" -ForegroundColor Red
                    Write-Host "    -> $($p.ProcessName) (PID: $($p.Id)) | Path: $filePath" -ForegroundColor DarkRed
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                    $killedCount++
                    break
                }
            }
        }
    } catch { }
}

if ($killedCount -eq 0) {
    Write-Host "  [BERSIH] Tidak ada proses infostealer aktif yang mencurigakan." -ForegroundColor Green
} else {
    Write-Host "  [OK] Total $killedCount proses jahat berhasil dihentikan." -ForegroundColor Green
}
Write-Host ""

# ----------------------------------------------------------
# 2. PEMBERSIHAN FOLDER TEMA WINDOWS
# ----------------------------------------------------------
Write-Host "[2/5] Memeriksa folder tema sistem (C:\Windows\Resources\Themes)..." -ForegroundColor Yellow

$themesDir = "C:\Windows\Resources\Themes"
$quarantinedFiles = 0

if (Test-Path $themesDir) {
    $illegalFiles = Get-ChildItem -Path $themesDir -Recurse -File -Include *.exe,*.scr,*.bat,*.cmd,*.vbs,*.ps1,*.icn -ErrorAction SilentlyContinue
    if ($illegalFiles.Count -eq 0) {
        Write-Host "  [BERSIH] Folder tema Windows bersih (tidak ada file biner terlarang)." -ForegroundColor Green
    } else {
        foreach ($f in $illegalFiles) {
            try {
                $destName = $f.Name + "_" + (Get-Date -Format "yyyyMMddHHmmss") + ".quarantined"
                $destPath = Join-Path $quarantineDir $destName
                
                # XOR Obfuscation (Key 0x5A) agar malware lumpuh permanen
                $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                for ($i = 0; $i -lt $bytes.Length; $i++) {
                    $bytes[$i] = $bytes[$i] -bxor 0x5A
                }
                [System.IO.File]::WriteAllBytes($destPath, $bytes)
                Remove-Item -Path $f.FullName -Force -ErrorAction Stop
                
                Write-Host "  [KARANTINA] Berkas jahat disamarkan & dikarantina:" -ForegroundColor Red
                Write-Host "    -> $($f.Name) di $($f.DirectoryName)" -ForegroundColor DarkYellow
                $quarantinedFiles++
            } catch {
                Write-Host "  [GAGAL] Tidak dapat memindahkan $($f.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
} else {
    Write-Host "  [INFO] Folder $themesDir tidak ditemukan." -ForegroundColor Gray
}
Write-Host ""

# ----------------------------------------------------------
# 3. PEMBERSIHAN REGISTRY AUTORUN
# ----------------------------------------------------------
Write-Host "[3/5] Memeriksa dan membersihkan entri Registry Autorun..." -ForegroundColor Yellow

$regCleaned = 0

# HKLM WOW6432Node
$badHklm = @("Explorer", "Svchost", "icsys", "mofk")
foreach ($v in $badHklm) {
    try {
        $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name $v -ErrorAction SilentlyContinue).$v
        if ($val) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name $v -Force -ErrorAction SilentlyContinue
            Write-Host "  [TERHAPUS] Autorun HKLM WOW6432Node: $v -> $val" -ForegroundColor Red
            $regCleaned++
        }
    } catch { }
}

# HKLM Standard
foreach ($v in $badHklm) {
    try {
        $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $v -ErrorAction SilentlyContinue).$v
        if ($val) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $v -Force -ErrorAction SilentlyContinue
            Write-Host "  [TERHAPUS] Autorun HKLM: $v -> $val" -ForegroundColor Red
            $regCleaned++
        }
    } catch { }
}

# HKCU (Current User) Run & RunOnce
$userKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($uk in $userKeys) {
    if (Test-Path $uk) {
        $props = (Get-Item $uk).Property
        foreach ($p in $props) {
            $val = (Get-ItemProperty -Path $uk -Name $p).$p
            if ($val -and ($val -match '(?i)(Resources\\Themes|AppData\\Local\\Temp|icsys|mofk|powershell.*-enc|wscript.*\.vbs)')) {
                Remove-ItemProperty -Path $uk -Name $p -Force -ErrorAction SilentlyContinue
                Write-Host "  [TERHAPUS] Autorun HKCU Jahat: $p -> $val" -ForegroundColor Red
                $regCleaned++
            }
        }
    }
}

if ($regCleaned -eq 0) {
    Write-Host "  [BERSIH] Entri Registry Autorun bersih dari entri mencurigakan." -ForegroundColor Green
} else {
    Write-Host "  [OK] Berhasil menghapus $regCleaned entri Registry jahat." -ForegroundColor Green
}
Write-Host ""

# ----------------------------------------------------------
# 4. PEMBERSIHAN SAMPAH EKSFILTRASI DI %TEMP%
# ----------------------------------------------------------
Write-Host "[4/5] Menyapu sampah staging eksfiltrasi stealer di %TEMP%..." -ForegroundColor Yellow

$tempPaths = @($env:TEMP, (Join-Path $env:LOCALAPPDATA "Temp"))
$deletedDumps = 0

foreach ($tp in $tempPaths) {
    if (Test-Path $tp) {
        $dumps = Get-ChildItem -Path $tp -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '(?i)^(passwords?\.txt|cookies?\.txt|autofill\.txt|wallets?|cards?\.txt|all_cookies\.txt)$' -or
            ($_.Name -match '(?i)^[a-f0-9]{16,32}\.zip$')
        }
        
        foreach ($d in $dumps) {
            try {
                Remove-Item -Path $d.FullName -Force -ErrorAction SilentlyContinue
                Write-Host "  [TERHAPUS] Berkas dump curian: $($d.Name)" -ForegroundColor Red
                $deletedDumps++
            } catch { }
        }
    }
}

if ($deletedDumps -eq 0) {
    Write-Host "  [BERSIH] Tidak ditemukan file dump eksfiltrasi aktif di folder Temp." -ForegroundColor Green
} else {
    Write-Host "  [OK] Berhasil membersihkan $deletedDumps berkas dump eksfiltrasi." -ForegroundColor Green
}
Write-Host ""

# ----------------------------------------------------------
# 5. INTEGRASI & JEMBATAN KE STEALERHUNTER GUI
# ----------------------------------------------------------
Write-Host "[5/5] Memeriksa instalasi StealerHunter GUI..." -ForegroundColor Yellow

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$candidatePaths = @(
    (Join-Path $scriptDir "StealerHunter\publish\win-x64\StealerHunter.exe"),
    (Join-Path $scriptDir "StealerHunter\bin\Release\net8.0-windows\win-x64\StealerHunter.exe"),
    (Join-Path $env:ProgramFiles "StealerHunter\StealerHunter.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\StealerHunter\StealerHunter.exe")
)

$shExe = $null
foreach ($cp in $candidatePaths) {
    if (Test-Path $cp) {
        $shExe = $cp
        break
    }
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  PEMBERSIHAN PERTOLONGAN PERTAMA BERHASIL DISELESAIKAN! " -ForegroundColor Green
Write-Host "  Folder Karantina: $quarantineDir" -ForegroundColor DarkGray
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

if ($shExe) {
    Write-Host "[REKOMENDASI] StealerHunter GUI ditemukan di sistem ini." -ForegroundColor Cyan
    Write-Host "Untuk memeriksa Master File Table (MFT) & mencocokkan 1.230+ signature Abuse.ch," -ForegroundColor Gray
    Write-Host "sangat disarankan melakukan Deep Scan lengkap." -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Buka StealerHunter sekarang? (Y/T)"
    if ($choice -match '^[yY]') {
        Write-Host "Meluncurkan StealerHunter..." -ForegroundColor Green
        Start-Process -FilePath $shExe
    }
} else {
    Write-Host "[INFO] Untuk proteksi real-time dan pencocokan 1.230+ hash Abuse.ch," -ForegroundColor Cyan
    Write-Host "jalankan installer StealerHunter_Setup_v1.1.0.exe." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Laporan selesai. Silakan periksa hasil di atas." -ForegroundColor White
Read-Host "Tekan [ENTER] untuk menutup jendela ini"
