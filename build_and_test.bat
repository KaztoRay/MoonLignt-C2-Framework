@echo off
REM CardinalOS v4.0 - Build and Test Script for Windows
REM Requires: GCC MinGW-w64, Python 3, QEMU (optional)

echo.
echo ========================================
echo   CardinalOS v4.0 Build System
echo ========================================
echo.

REM Check if GCC is available
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] GCC not found! Please install MinGW-w64
    echo Download from: https://www.mingw-w64.org/
    pause
    exit /b 1
)

echo [1/5] Compiling CardinalOS v4.0...
gcc -o cardinalos_v4.exe cardinalos_v4.c -O3 -march=native -s -ffast-math -funroll-loops 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Compilation failed!
    pause
    exit /b 1
)
echo [OK] Compilation successful: cardinalos_v4.exe

echo.
echo [2/5] Testing executable...
echo.

REM Test the executable
start "" cardinalos_v4.exe

echo.
echo [3/5] Checking for Python...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Python not found, skipping ISO generation
    goto skip_iso
)

echo [OK] Python found
echo.
echo [4/5] Attempting ISO generation...
echo.

REM Try to generate ISO (will fail gracefully if tools not available)
python create_iso.py

:skip_iso

echo.
echo [5/5] Checking for QEMU...
where qemu-system-x86_64 >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] QEMU not found, skipping emulation test
    goto end
)

echo [OK] QEMU found
echo.
echo Would you like to test the ISO with QEMU? (Y/N)
set /p choice=

if /i "%choice%"=="Y" (
    for %%f in (CardinalOS-*.iso) do (
        echo Starting QEMU with %%f...
        qemu-system-x86_64 -cdrom "%%f" -m 512M -boot d
        goto end
    )
    echo [WARNING] No ISO file found
)

:end
echo.
echo ========================================
echo   Build Complete
echo ========================================
echo.
echo Executable: cardinalos_v4.exe
echo.
echo To run CardinalOS:
echo   .\cardinalos_v4.exe
echo.
echo To test with QEMU (if ISO exists):
echo   qemu-system-x86_64 -cdrom CardinalOS-*.iso -m 512M -boot d
echo.
pause
