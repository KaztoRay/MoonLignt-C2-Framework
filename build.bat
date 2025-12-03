@echo off
echo ============================================
echo Moonlight C2 Framework - Simple Build
echo ============================================
echo.

echo [*] Checking build tools...
echo.

where gcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] GCC not found!
    echo.
    echo Please install MinGW-w64:
    echo 1. Visit: https://winlibs.com/
    echo 2. Download: GCC 13.2.0 + MinGW-w64 11.0.1 ^(Win64^)
    echo 3. Extract to C:\mingw64
    echo 4. Add C:\mingw64\bin to PATH
    echo 5. Restart this terminal and run this script again
    echo.
    pause
    exit /b 1
)

where nasm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] NASM not found!
    echo.
    echo Please install NASM:
    echo 1. Visit: https://www.nasm.us/
    echo 2. Download: nasm-2.16.01-win64.zip
    echo 3. Extract to C:\nasm
    echo 4. Add C:\nasm to PATH
    echo 5. Restart this terminal and run this script again
    echo.
    pause
    exit /b 1
)

echo [+] GCC found!
echo [+] NASM found!
echo.

echo ============================================
echo Building Client...
echo ============================================
echo.

cd client

if not exist build\obj mkdir build\obj

echo [*] Compiling assembly modules...
nasm -f win64 stealth.asm -o build\obj\stealth.obj
if %ERRORLEVEL% NEQ 0 goto error

nasm -f win64 syscalls.asm -o build\obj\syscalls.obj
if %ERRORLEVEL% NEQ 0 goto error

nasm -f win64 network_asm.asm -o build\obj\network_asm.obj
if %ERRORLEVEL% NEQ 0 goto error

nasm -f win64 monitoring.asm -o build\obj\monitoring.obj
if %ERRORLEVEL% NEQ 0 goto error

nasm -f win64 control.asm -o build\obj\control.obj
if %ERRORLEVEL% NEQ 0 goto error

echo [*] Compiling C sources...
gcc -c implant_enhanced.c -o build\obj\implant_enhanced.o -Wall -O2
if %ERRORLEVEL% NEQ 0 goto error

gcc -c monitoring_control.c -o build\obj\monitoring_control.o -Wall -O2
if %ERRORLEVEL% NEQ 0 goto error

echo [*] Linking client...
gcc -o build\moonlight-implant-enhanced.exe build\obj\implant_enhanced.o build\obj\monitoring_control.o build\obj\stealth.obj build\obj\syscalls.obj build\obj\network_asm.obj build\obj\monitoring.obj build\obj\control.obj -lws2_32 -ladvapi32 -lgdi32 -luser32 -s
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Client built successfully!
echo.

cd ..

echo ============================================
echo Building Server...
echo ============================================
echo.

cd server

if not exist build\obj mkdir build\obj

echo [*] Compiling assembly modules...
nasm -f win64 ..\client\network_asm.asm -o build\obj\network_asm.obj
if %ERRORLEVEL% NEQ 0 goto error

echo [*] Compiling C source...
gcc -c main_enhanced.c -o build\obj\main_enhanced.o -Wall -O2 -DMAX_CLIENTS=100
if %ERRORLEVEL% NEQ 0 goto error

echo [*] Linking server...
gcc -o build\moonlight-server-enhanced.exe build\obj\main_enhanced.o build\obj\network_asm.obj -lws2_32 -lpthread -s
if %ERRORLEVEL% NEQ 0 goto error

echo [+] Server built successfully!
echo.

cd ..

echo ============================================
echo Building GUI...
echo ============================================
echo.

cd gui

echo [*] Compiling GUI...
gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0501 -mwindows main.c -o MoonlightC2-GUI.exe -lcomctl32 -lws2_32 -lgdi32 -lcomdlg32 -s
if %ERRORLEVEL% NEQ 0 goto error

echo [+] GUI built successfully!
echo.

cd ..

echo ============================================
echo Installing binaries...
echo ============================================
echo.

if not exist bin mkdir bin
if not exist bin\exploits mkdir bin\exploits

copy client\build\moonlight-implant-enhanced.exe bin\
copy server\build\moonlight-server-enhanced.exe bin\
copy gui\MoonlightC2-GUI.exe bin\

echo [+] Installation complete!
echo.

echo ============================================
echo Build Summary
echo ============================================
echo.
echo Client:  bin\moonlight-implant-enhanced.exe
echo Server:  bin\moonlight-server-enhanced.exe
echo GUI:     bin\MoonlightC2-GUI.exe
echo.
echo ============================================
echo Build completed successfully!
echo ============================================
echo.
echo Next steps:
echo   1. Start server: bin\moonlight-server-enhanced.exe
echo   2. Launch GUI:   bin\MoonlightC2-GUI.exe
echo.
pause
exit /b 0

:error
echo.
echo [!] Build failed!
echo.
pause
exit /b 1
