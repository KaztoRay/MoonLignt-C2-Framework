@echo off
echo ============================================
echo CardinalOS Build Script for Windows
echo ============================================
echo.

REM Check for required tools
echo [*] Checking build tools...
echo.

where gcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] GCC not found! Please install MinGW-w64
    pause
    exit /b 1
)

where nasm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] NASM not found! Please install NASM
    pause
    exit /b 1
)

where make >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Make not found! Please install GNU Make
    pause
    exit /b 1
)

echo [+] All build tools found!
echo.

REM Create build directory
if not exist build mkdir build
if not exist iso\boot\grub mkdir iso\boot\grub

echo ============================================
echo Building CardinalOS
echo ============================================
echo.

REM Build bootloader
echo [*] Building bootloader...
nasm -f bin boot\boot.asm -o build\boot.bin
if %ERRORLEVEL% NEQ 0 goto error

nasm -f bin boot\stage2.asm -o build\stage2.bin
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Bootloader built successfully
echo.

REM Build kernel
echo [*] Building kernel...
gcc -m64 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector ^
    -mno-red-zone -mcmodel=large -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra ^
    -Ikernel -O2 -c kernel\main.c -o build\main.o
if %ERRORLEVEL% NEQ 0 goto error

gcc -m64 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector ^
    -mno-red-zone -mcmodel=large -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra ^
    -Ikernel -O2 -c kernel\mm\memory.c -o build\memory.o
if %ERRORLEVEL% NEQ 0 goto error

gcc -m64 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector ^
    -mno-red-zone -mcmodel=large -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra ^
    -Ikernel -O2 -c kernel\net\network.c -o build\network.o
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Kernel compiled successfully
echo.

REM Build C2 core
echo [*] Building C2 core...
gcc -m64 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector ^
    -mno-red-zone -mcmodel=large -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra ^
    -Ikernel -O2 -c c2\c2_core.c -o build\c2_core.o
if %ERRORLEVEL% NEQ 0 goto error

echo [+] C2 core compiled successfully
echo.

REM Build shell
echo [*] Building shell...
gcc -m64 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector ^
    -mno-red-zone -mcmodel=large -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra ^
    -Ikernel -O2 -c shell\shell.c -o build\shell.o
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Shell compiled successfully
echo.

REM Build VFS
echo [*] Building filesystem...
gcc -m64 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector ^
    -mno-red-zone -mcmodel=large -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra ^
    -Ikernel -O2 -c fs\vfs.c -o build\vfs.o
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Filesystem compiled successfully
echo.

REM Link kernel
echo [*] Linking kernel...
ld -T linker.ld -nostdlib -o build\kernel.bin ^
    build\main.o build\memory.o build\network.o ^
    build\c2_core.o build\shell.o build\vfs.o
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Kernel linked successfully
echo.

REM Create disk image
echo [*] Creating disk image...
fsutil file createnew build\cardinalos.img 33554432 >nul
if %ERRORLEVEL% NEQ 0 goto error

REM Write bootloader and kernel to image
echo [*] Writing bootloader...
REM Note: This is simplified. In production, use dd or custom tool
copy /b build\boot.bin + build\stage2.bin + build\kernel.bin build\cardinalos.img >nul

echo [+] Disk image created: build\cardinalos.img
echo.

REM Build Windows EXE wrapper
echo [*] Building Windows launcher...
gcc -o build\cardinalos.exe tools\win_wrapper.c -DIMG_FILE=\"build/cardinalos.img\"
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Windows launcher created: build\cardinalos.exe
echo.

echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Output files:
echo   - build\cardinalos.img  (Disk image for QEMU/VirtualBox)
echo   - build\cardinalos.exe  (Windows launcher)
echo.
echo To run in QEMU:
echo   qemu-system-x86_64 -drive format=raw,file=build\cardinalos.img -m 128M
echo.
echo To run on Windows:
echo   build\cardinalos.exe
echo.
pause
exit /b 0

:error
echo.
echo [!] Build failed!
echo.
pause
exit /b 1
