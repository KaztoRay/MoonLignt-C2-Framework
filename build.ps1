# Moonlight C2 Framework - Master Build Script
# PowerShell Build Automation

$ErrorActionPreference = "Stop"

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  Moonlight C2 Framework - Builder  " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "For Authorized Penetration Testing Only`n" -ForegroundColor Yellow

# Check for required tools
function Test-Tool {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

Write-Host "[*] Checking build tools..." -ForegroundColor Yellow

$hasGCC = Test-Tool "gcc"
$hasMSBuild = Test-Tool "msbuild"
$hasDotnet = Test-Tool "dotnet"
$hasNasm = Test-Tool "nasm"

if (-not $hasGCC) {
    Write-Host "[!] GCC not found. Please install MinGW-w64" -ForegroundColor Red
    Write-Host "    Download: https://mingw-w64.org/" -ForegroundColor Yellow
}

if (-not $hasDotnet) {
    Write-Host "[!] .NET SDK not found. Please install .NET Framework 4.8" -ForegroundColor Red
    Write-Host "    Download: https://dotnet.microsoft.com/download" -ForegroundColor Yellow
}

if (-not $hasNasm) {
    Write-Host "[!] NASM not found. Installing is optional (for shellcode)" -ForegroundColor Yellow
    Write-Host "    Download: https://www.nasm.us/" -ForegroundColor Yellow
}

Write-Host ""

# Create bin directory
if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
    Write-Host "[+] Created bin directory" -ForegroundColor Green
}

if (-not (Test-Path "bin\exploits")) {
    New-Item -ItemType Directory -Path "bin\exploits" | Out-Null
    Write-Host "[+] Created bin\exploits directory" -ForegroundColor Green
}

# Build Server
Write-Host "`n[*] Building C2 Server..." -ForegroundColor Cyan
Push-Location server
try {
    if ($hasGCC) {
        & gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0500 main.c -o moonlight-server.exe -lws2_32
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Server compiled successfully" -ForegroundColor Green
            Copy-Item moonlight-server.exe ..\bin\ -Force
        } else {
            Write-Host "[!] Server compilation failed" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "[!] Error building server: $_" -ForegroundColor Red
}
Pop-Location

# Build Client
Write-Host "`n[*] Building C2 Client/Implant..." -ForegroundColor Cyan
Push-Location client
try {
    if ($hasGCC) {
        & gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0500 -mwindows implant.c -o moonlight-implant.exe -lws2_32 -ladvapi32 -luser32
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Client compiled successfully" -ForegroundColor Green
            Copy-Item moonlight-implant.exe ..\bin\ -Force
        } else {
            Write-Host "[!] Client compilation failed" -ForegroundColor Red
        }
    }
    
    # Build shellcode
    if ($hasNasm) {
        & nasm -f bin -o shellcode.bin shellcode.asm
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Shellcode compiled successfully" -ForegroundColor Green
            Copy-Item shellcode.bin ..\bin\ -Force
        }
    }
} catch {
    Write-Host "[!] Error building client: $_" -ForegroundColor Red
}
Pop-Location

# Build Exploits
Write-Host "`n[*] Building Exploit Modules..." -ForegroundColor Cyan
Push-Location exploits
try {
    if ($hasGCC) {
        $exploits = @(
            @{Name="MS08-067"; Source="ms08_067.c"; Output="ms08-067.exe"},
            @{Name="MS03-026"; Source="ms03_026.c"; Output="ms03-026.exe"},
            @{Name="MS17-010"; Source="ms17_010.c"; Output="ms17-010.exe"}
        )
        
        foreach ($exploit in $exploits) {
            Write-Host "  [*] Building $($exploit.Name)..." -ForegroundColor Yellow
            & gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0500 $exploit.Source -o $exploit.Output -lws2_32
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [+] $($exploit.Name) compiled" -ForegroundColor Green
                Copy-Item $exploit.Output ..\bin\exploits\ -Force
            } else {
                Write-Host "  [!] $($exploit.Name) compilation failed" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "[!] Error building exploits: $_" -ForegroundColor Red
}
Pop-Location

# Build GUI
Write-Host "`n[*] Building GUI Application..." -ForegroundColor Cyan
Push-Location gui
try {
    if ($hasDotnet) {
        & dotnet build MoonlightC2.csproj -c Release -o ..\bin\gui
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] GUI compiled successfully" -ForegroundColor Green
        } else {
            Write-Host "[!] GUI compilation failed" -ForegroundColor Red
        }
    } elseif ($hasMSBuild) {
        & msbuild MoonlightC2.csproj /p:Configuration=Release /p:OutputPath=..\bin\gui
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] GUI compiled successfully" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "[!] Error building GUI: $_" -ForegroundColor Red
}
Pop-Location

# Summary
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  Build Summary" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$binFiles = Get-ChildItem -Path "bin" -Recurse -File

Write-Host "`nBuilt files:" -ForegroundColor Green
foreach ($file in $binFiles) {
    $relativePath = $file.FullName.Substring((Get-Location).Path.Length + 1)
    Write-Host "  $relativePath" -ForegroundColor White
}

Write-Host "`n[+] Build process completed!" -ForegroundColor Green
Write-Host "[*] Binaries are in the 'bin' directory" -ForegroundColor Yellow
Write-Host "`n[!] WARNING: Use only for authorized penetration testing!" -ForegroundColor Red
