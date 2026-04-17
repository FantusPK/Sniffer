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
    pause
    exit /b 1
)

echo [1/3] Installing package + build deps...
pip install -e ".[build]" --quiet
if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
)
echo       Done.
echo.

echo [2/3] Cleaning old build...
if exist dist\Sniffer.exe del /f /q dist\Sniffer.exe
if exist build rmdir /s /q build
echo       Done.
echo.

echo [3/3] Building exe...
python -m PyInstaller --onefile --windowed --name Sniffer src\sniffer\__main__.py
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    pause
    exit /b 1
)
echo.
echo ================================
echo  Build complete!
echo  Exe: dist\Sniffer.exe
echo ================================
echo.
pause
