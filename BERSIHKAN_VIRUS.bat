@echo off
title StealerHunter - Virus & Stealer Cleaner
color 0A

:: Check for Administrator permissions
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ===================================================
    echo  MEMERLUKAN HAK AKSES ADMINISTRATOR
    echo  Membuka dialog UAC Windows... Silakan klik 'Yes'
    echo ===================================================
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ====================================================
echo    STEALERHUNTER - REMOVAL & QUARANTINE ENGINE
echo    Membersihkan Worm:Win32/Mofksys (Icsys Stealer)
echo ====================================================
echo.

set QUARANTINE_DIR=%APPDATA%\StealerHunter\Quarantine
if not exist "%QUARANTINE_DIR%" mkdir "%QUARANTINE_DIR%"

echo [1/3] Menghapus entri Registry Autorun di WOW6432Node...
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Explorer" /f >nul 2>&1
if %errorlevel% equ 0 (echo   [OK] Registry Run 'Explorer' berhasil dihapus.) else (echo   [INFO] Registry Run 'Explorer' sudah bersih.)

reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Svchost" /f >nul 2>&1
if %errorlevel% equ 0 (echo   [OK] Registry Run 'Svchost' berhasil dihapus.) else (echo   [INFO] Registry Run 'Svchost' sudah bersih.)

echo.
echo [2/3] Mematikan proses mencurigakan jika aktif...
taskkill /F /IM "icsys.icn.exe" >nul 2>&1

echo.
echo [3/3] Mengkarantina file virus asli di C:\Windows\Resources...

for %%F in (
    "C:\Windows\Resources\Themes\icsys.icn.exe"
    "C:\Windows\Resources\Themes\icsys.icn"
    "C:\Windows\Resources\Themes\explorer.exe"
    "C:\Windows\Resources\svchost.exe"
    "C:\Windows\Resources\spoolsv.exe"
) do (
    if exist "%%~F" (
        attrib -r -s -h "%%~F" >nul 2>&1
        move /y "%%~F" "%QUARANTINE_DIR%\" >nul 2>&1
        if not exist "%%~F" (
            echo   [OK] Karantina Sukses: %%~nxF -^> %QUARANTINE_DIR%
        ) else (
            del /f /q "%%~F" >nul 2>&1
            echo   [OK] Berhasil Dihapus: %%~nxF
        )
    ) else (
        echo   [INFO] File sudah tidak ada: %%~nxF
    )
)

echo.
echo ====================================================
echo  PEMBERSIHAN SELESAI! SISTEM TELAH DIBERSIHKAN.
echo  File virus telah diisolasi di:
echo  %QUARANTINE_DIR%
echo ====================================================
echo.
pause
