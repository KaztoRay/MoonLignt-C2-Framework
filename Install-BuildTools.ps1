# Moonlight C2 Framework - Build Tools Installer
# This script downloads and installs MinGW-w64 and NASM

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Moonlight C2 Framework - Build Tools Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] 이 스크립트는 관리자 권한이 필요합니다." -ForegroundColor Red
    Write-Host "[*] PowerShell을 관리자 권한으로 실행한 후 다시 시도하세요." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "방법: PowerShell 우클릭 -> '관리자 권한으로 실행'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "[*] 관리자 권한 확인됨" -ForegroundColor Green
Write-Host ""

# Create tools directory
$toolsDir = "C:\BuildTools"
if (-not (Test-Path $toolsDir)) {
    Write-Host "[*] 빌드 도구 디렉토리 생성: $toolsDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
}

# Download URLs
$mingwUrl = "https://github.com/niXman/mingw-builds-binaries/releases/download/13.2.0-rt_v11-rev1/x86_64-13.2.0-release-posix-seh-ucrt-rt_v11-rev1.7z"
$nasmUrl = "https://www.nasm.us/pub/nasm/releasebuilds/2.16.01/win64/nasm-2.16.01-win64.zip"

# Install 7-Zip if not present (needed to extract .7z)
Write-Host "[*] 7-Zip 확인 중..." -ForegroundColor Yellow
$7zipPath = "C:\Program Files\7-Zip\7z.exe"
if (-not (Test-Path $7zipPath)) {
    Write-Host "[*] 7-Zip이 설치되어 있지 않습니다. 수동 설치가 필요합니다." -ForegroundColor Red
    Write-Host "[*] 다음 링크에서 다운로드: https://www.7-zip.org/download.html" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "또는 다음 명령어로 Chocolatey를 설치한 후 진행하세요:" -ForegroundColor Yellow
    Write-Host "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Chocolatey 설치 후:" -ForegroundColor Yellow
    Write-Host "choco install 7zip mingw nasm make -y" -ForegroundColor Cyan
    pause
    exit 1
}

Write-Host "[+] 7-Zip 발견" -ForegroundColor Green

# Download MinGW
Write-Host ""
Write-Host "[*] MinGW-w64 다운로드 중..." -ForegroundColor Yellow
$mingwZip = "$toolsDir\mingw.7z"
try {
    Invoke-WebRequest -Uri $mingwUrl -OutFile $mingwZip -UseBasicParsing
    Write-Host "[+] MinGW 다운로드 완료" -ForegroundColor Green
} catch {
    Write-Host "[!] MinGW 다운로드 실패: $_" -ForegroundColor Red
    pause
    exit 1
}

# Extract MinGW
Write-Host "[*] MinGW 압축 해제 중..." -ForegroundColor Yellow
$mingwDir = "$toolsDir\mingw64"
if (Test-Path $mingwDir) {
    Remove-Item $mingwDir -Recurse -Force
}
& $7zipPath x $mingwZip "-o$toolsDir" -y | Out-Null
Write-Host "[+] MinGW 압축 해제 완료" -ForegroundColor Green

# Download NASM
Write-Host ""
Write-Host "[*] NASM 다운로드 중..." -ForegroundColor Yellow
$nasmZip = "$toolsDir\nasm.zip"
try {
    Invoke-WebRequest -Uri $nasmUrl -OutFile $nasmZip -UseBasicParsing
    Write-Host "[+] NASM 다운로드 완료" -ForegroundColor Green
} catch {
    Write-Host "[!] NASM 다운로드 실패: $_" -ForegroundColor Red
    pause
    exit 1
}

# Extract NASM
Write-Host "[*] NASM 압축 해제 중..." -ForegroundColor Yellow
Expand-Archive -Path $nasmZip -DestinationPath $toolsDir -Force
$nasmExtracted = Get-ChildItem -Path $toolsDir -Filter "nasm-*" -Directory | Select-Object -First 1
$nasmDir = "$toolsDir\nasm"
if (Test-Path $nasmDir) {
    Remove-Item $nasmDir -Recurse -Force
}
Rename-Item -Path $nasmExtracted.FullName -NewName "nasm"
Write-Host "[+] NASM 압축 해제 완료" -ForegroundColor Green

# Add to PATH
Write-Host ""
Write-Host "[*] PATH 환경변수 업데이트 중..." -ForegroundColor Yellow
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$mingwBinPath = "$mingwDir\bin"
$nasmBinPath = $nasmDir

if ($currentPath -notlike "*$mingwBinPath*") {
    [Environment]::SetEnvironmentVariable("Path", $currentPath + ";$mingwBinPath", "Machine")
    Write-Host "[+] MinGW를 PATH에 추가했습니다" -ForegroundColor Green
} else {
    Write-Host "[*] MinGW가 이미 PATH에 있습니다" -ForegroundColor Yellow
}

if ($currentPath -notlike "*$nasmBinPath*") {
    [Environment]::SetEnvironmentVariable("Path", $currentPath + ";$mingwBinPath;$nasmBinPath", "Machine")
    Write-Host "[+] NASM을 PATH에 추가했습니다" -ForegroundColor Green
} else {
    Write-Host "[*] NASM이 이미 PATH에 있습니다" -ForegroundColor Yellow
}

# Update current session PATH
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine")

# Verify installation
Write-Host ""
Write-Host "[*] 설치 확인 중..." -ForegroundColor Yellow
Write-Host ""

try {
    $gccVersion = & "$mingwBinPath\gcc.exe" --version 2>&1 | Select-Object -First 1
    Write-Host "[+] GCC: $gccVersion" -ForegroundColor Green
} catch {
    Write-Host "[!] GCC 확인 실패" -ForegroundColor Red
}

try {
    $nasmVersion = & "$nasmBinPath\nasm.exe" -v 2>&1
    Write-Host "[+] NASM: $nasmVersion" -ForegroundColor Green
} catch {
    Write-Host "[!] NASM 확인 실패" -ForegroundColor Red
}

# Cleanup
Write-Host ""
Write-Host "[*] 임시 파일 정리 중..." -ForegroundColor Yellow
Remove-Item $mingwZip -Force -ErrorAction SilentlyContinue
Remove-Item $nasmZip -Force -ErrorAction SilentlyContinue
Write-Host "[+] 정리 완료" -ForegroundColor Green

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "빌드 도구 설치 완료!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "설치 위치:" -ForegroundColor Cyan
Write-Host "  - MinGW: $mingwDir" -ForegroundColor White
Write-Host "  - NASM:  $nasmDir" -ForegroundColor White
Write-Host ""
Write-Host "다음 단계:" -ForegroundColor Yellow
Write-Host "  1. 이 PowerShell 창을 닫고 새로운 PowerShell 창을 엽니다" -ForegroundColor White
Write-Host "  2. 프로젝트 디렉토리로 이동합니다" -ForegroundColor White
Write-Host "  3. .\Build-All.ps1 실행하여 프로젝트를 빌드합니다" -ForegroundColor White
Write-Host ""

pause
