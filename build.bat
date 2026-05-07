@echo off
title Sniffer - Build Executable
echo.
echo ================================
echo  Sniffer - Build Executable
echo ================================
echo.

where pip >nul 2>&1
if errorlevel 1 (
    echo ERROR: pip not found. Install Python 3.10+ from https://python.org
    exit /b 1
)

echo [1/4] Installing package + build deps...
ping -n 1 -w 1000 8.8.8.8 >nul 2>&1
if errorlevel 1 (
    echo       Offline - skipping dependency fetch.
) else (
    pip install -e ".[build]" --quiet
    if errorlevel 1 (
        echo ERROR: pip install failed.
        exit /b 1
    )
    echo       Done.
)
echo.

echo [2/4] Closing any running Sniffer instance...
if "%1"=="REBUILD" (
    echo       Skipped ^(called from running app^).
) else (
    taskkill /f /im Sniffer.exe >nul 2>&1
    echo       Done.
)
echo.

echo [3/4] Cleaning old build...
if exist dist\Sniffer.exe del /f /q dist\Sniffer.exe >nul 2>&1
if exist build rmdir /s /q build
echo       Done.
echo.

echo [4/4] Building exe...
python -m PyInstaller Sniffer.spec
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    exit /b 1
)
echo.
echo ================================
echo  Build complete!
echo  Exe: dist\Sniffer.exe
echo ================================
echo.

if not "%1"=="REBUILD" (
    echo Launching Sniffer...
    start "" "dist\Sniffer.exe"
)
exit /b 0
