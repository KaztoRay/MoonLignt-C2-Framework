# Moonlight C2 Framework - 순수 C 빌드 스크립트
# 어셈블리 제거, GUI 서버 추가

param(
    [switch]$Client,
    [switch]$Server,
    [switch]$GUIServer,
    [switch]$Exploits,
    [switch]$Clean,
    [switch]$All
)

$ErrorActionPreference = "Continue"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Moonlight C2 Framework - Pure C Build" -ForegroundColor Green
Write-Host "============================================`n" -ForegroundColor Cyan

# 빌드 디렉토리 생성
if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

# 클린 옵션
if ($Clean) {
    Write-Host "[*] Cleaning build artifacts..." -ForegroundColor Yellow
    Remove-Item -Path "bin\*" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "client\build\*" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "server\build\*" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "gui\build\*" -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Clean complete`n" -ForegroundColor Green
    return
}

# 모두 빌드
if ($All -or (-not $Client -and -not $Server -and -not $GUIServer -and -not $Exploits)) {
    $Client = $true
    $Server = $true
    $GUIServer = $true
    $Exploits = $true
}

$success = $true

# =============================================================================
# 클라이언트 빌드 (순수 C)
# =============================================================================
if ($Client) {
    Write-Host "[*] Building Client Implant (Pure C)..." -ForegroundColor Cyan
    
    if (-not (Test-Path "client\build")) {
        New-Item -ItemType Directory -Path "client\build" | Out-Null
    }
    
    Push-Location client
    
    # stealth.c와 network.c 컴파일
    Write-Host "  [+] Compiling stealth module..." -ForegroundColor Gray
    gcc -c stealth.c -o build/stealth.o -O2 -Wall
    
    Write-Host "  [+] Compiling network module..." -ForegroundColor Gray
    gcc -c network.c -o build/network.o -O2 -Wall
    
    Write-Host "  [+] Compiling main implant..." -ForegroundColor Gray
    gcc -c implant.c -o build/implant.o -O2 -Wall
    
    # 링크
    Write-Host "  [+] Linking..." -ForegroundColor Gray
    gcc build/implant.o build/stealth.o build/network.o `
        -o build/moonlight-implant.exe `
        -lws2_32 -ladvapi32 -luser32 -s -O2
    
    if ($LASTEXITCODE -eq 0) {
        Copy-Item "build\moonlight-implant.exe" "..\bin\" -Force
        Write-Host "[+] Client build successful!" -ForegroundColor Green
        $size = (Get-Item "..\bin\moonlight-implant.exe").Length / 1KB
        Write-Host "    Size: $([math]::Round($size, 2)) KB`n" -ForegroundColor Gray
    } else {
        Write-Host "[!] Client build failed" -ForegroundColor Red
        $success = $false
    }
    
    Pop-Location
}

# =============================================================================
# 콘솔 서버 빌드
# =============================================================================
if ($Server) {
    Write-Host "[*] Building Console Server..." -ForegroundColor Cyan
    
    if (-not (Test-Path "server\build")) {
        New-Item -ItemType Directory -Path "server\build" | Out-Null
    }
    
    Push-Location server
    
    gcc main.c -o build\moonlight-server.exe -lws2_32 -s -O2
    
    if ($LASTEXITCODE -eq 0) {
        Copy-Item "build\moonlight-server.exe" "..\bin\" -Force
        Write-Host "[+] Console Server build successful!" -ForegroundColor Green
        $size = (Get-Item "..\bin\moonlight-server.exe").Length / 1KB
        Write-Host "    Size: $([math]::Round($size, 2)) KB`n" -ForegroundColor Gray
    } else {
        Write-Host "[!] Console Server build failed" -ForegroundColor Red
        $success = $false
    }
    
    Pop-Location
}

# =============================================================================
# GUI 서버 빌드
# =============================================================================
if ($GUIServer) {
    Write-Host "[*] Building GUI Server (Hacker Theme)..." -ForegroundColor Cyan
    
    if (-not (Test-Path "server\build")) {
        New-Item -ItemType Directory -Path "server\build" | Out-Null
    }
    
    Push-Location server
    
    # GUI 컴포넌트 컴파일
    Write-Host "  [+] Compiling GUI components..." -ForegroundColor Gray
    gcc -c gui_server.c -o build/gui_server.o -O2 -Wall -mwindows
    gcc -c gui_server_functions.c -o build/gui_server_functions.o -O2 -Wall
    gcc -c main.c -o build/server_backend.o -O2 -Wall -DGUI_MODE
    
    # 링크 (Windows GUI 모드)
    Write-Host "  [+] Linking GUI server..." -ForegroundColor Gray
    gcc build/gui_server.o build/gui_server_functions.o build/server_backend.o `
        -o build/moonlight-gui-server.exe `
        -lws2_32 -lcomctl32 -lgdi32 -luser32 -lcomdlg32 `
        -mwindows -s -O2
    
    if ($LASTEXITCODE -eq 0) {
        Copy-Item "build\moonlight-gui-server.exe" "..\bin\" -Force
        Write-Host "[+] GUI Server build successful!" -ForegroundColor Green
        $size = (Get-Item "..\bin\moonlight-gui-server.exe").Length / 1KB
        Write-Host "    Size: $([math]::Round($size, 2)) KB`n" -ForegroundColor Gray
    } else {
        Write-Host "[!] GUI Server build failed" -ForegroundColor Red
        Write-Host "    Note: GUI build requires proper linking" -ForegroundColor Yellow
        $success = $false
    }
    
    Pop-Location
}

# =============================================================================
# Exploits 빌드
# =============================================================================
if ($Exploits) {
    Write-Host "[*] Building Exploits..." -ForegroundColor Cyan
    
    Push-Location exploits
    
    if (Test-Path "Makefile") {
        make clean 2>$null | Out-Null
        make all
        
        if ($LASTEXITCODE -eq 0) {
            Copy-Item "*.exe" "..\bin\" -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Exploits build successful!`n" -ForegroundColor Green
        } else {
            Write-Host "[!] Exploits build failed`n" -ForegroundColor Red
            $success = $false
        }
    } else {
        Write-Host "[!] Makefile not found in exploits directory`n" -ForegroundColor Red
    }
    
    Pop-Location
}

# =============================================================================
# 빌드 요약
# =============================================================================
Write-Host "`n============================================" -ForegroundColor Cyan
if ($success) {
    Write-Host " Build Complete - All Success! ✓" -ForegroundColor Green
} else {
    Write-Host " Build Complete - Some Failures" -ForegroundColor Yellow
}
Write-Host "============================================`n" -ForegroundColor Cyan

Write-Host "Built Components:" -ForegroundColor Cyan
Get-ChildItem bin\*.exe | ForEach-Object {
    $size = $_.Length / 1KB
    Write-Host "  ✓ $($_.Name) - $([math]::Round($size, 2)) KB" -ForegroundColor Green
}

Write-Host "`n[*] Build artifacts in: bin\" -ForegroundColor Gray
Write-Host "[*] Ready to deploy!`n" -ForegroundColor Green
