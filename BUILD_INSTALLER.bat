@echo off
title StealerHunter Installer Builder
echo ========================================================
echo         StealerHunter - Building Setup Installer
echo ========================================================
echo.

echo [1/3] Publishing Self-Contained .NET 8 (win-x64)...
dotnet publish StealerHunter\StealerHunter.csproj -c Release -r win-x64 --self-contained true -o StealerHunter\publish\win-x64
if %errorlevel% neq 0 (
    echo [ERROR] dotnet publish failed!
    pause
    exit /b %errorlevel%
)

echo.
echo [2/3] Locating Inno Setup Compiler (ISCC)...
set "ISCC_PATH=C:\Users\rohim\AppData\Local\Programs\Antigravity IDE\resources\app\node_modules\innosetup\bin\ISCC.exe"
if not exist "%ISCC_PATH%" set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" set "ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" (
    where iscc >nul 2>nul
    if %errorlevel% equ 0 (
        set "ISCC_PATH=iscc"
    ) else (
        echo [ERROR] Inno Setup compiler ISCC.exe not found!
        pause
        exit /b 1
    )
)

echo.
echo [3/3] Compiling Inno Setup script (StealerHunter_Setup.iss)...
"%ISCC_PATH%" "StealerHunter_Setup.iss"
if %errorlevel% neq 0 (
    echo [ERROR] Inno Setup compilation failed!
    pause
    exit /b %errorlevel%
)

echo.
echo  SUCCESS! Installer generated in:
echo  installer_output\
echo ========================================================
echo.
pause
