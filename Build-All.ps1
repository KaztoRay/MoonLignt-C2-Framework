# Moonlight C2 Framework - Master Build Script
# Builds entire C2 framework (client, server, exploits)

$ErrorActionPreference = "Stop"

# Configuration
$ROOT_DIR = $PSScriptRoot
$CLIENT_DIR = Join-Path $ROOT_DIR "client"
$SERVER_DIR = Join-Path $ROOT_DIR "server"
$EXPLOITS_DIR = Join-Path $ROOT_DIR "exploits"
$GUI_DIR = Join-Path $ROOT_DIR "gui"
$BIN_DIR = Join-Path $ROOT_DIR "bin"

# Colors for output
function Write-Success { Write-Host "[+] $args" -ForegroundColor Green }
function Write-Info { Write-Host "[*] $args" -ForegroundColor Cyan }
function Write-Error { Write-Host "[!] $args" -ForegroundColor Red }
function Write-Section { 
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  $args" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow
}

# Check for required tools
function Test-Prerequisites {
    Write-Section "Checking Prerequisites"
    
    $tools = @(
        @{Name="gcc"; Command="gcc --version"},
        @{Name="nasm"; Command="nasm -v"},
        @{Name="make"; Command="make --version"}
    )
    
    $missing = @()
    
    foreach ($tool in $tools) {
        Write-Info "Checking for $($tool.Name)..."
        try {
            $null = Invoke-Expression $tool.Command 2>&1
            Write-Success "$($tool.Name) found"
        }
        catch {
            Write-Error "$($tool.Name) not found"
            $missing += $tool.Name
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Error "Missing tools: $($missing -join ', ')"
        Write-Info "Please install MinGW-w64 and NASM"
        exit 1
    }
    
    Write-Success "All prerequisites satisfied"
}

# Build client components
function Build-Client {
    Write-Section "Building Client Components"
    
    Push-Location $CLIENT_DIR
    
    try {
        Write-Info "Building basic implant..."
        make basic
        Write-Success "Basic implant compiled"
        
        Write-Info "Building enhanced implant with assembly..."
        make enhanced
        Write-Success "Enhanced implant compiled"
        
        Write-Info "Building shellcode..."
        make shellcode
        Write-Success "Shellcode compiled"
    }
    catch {
        Write-Error "Client build failed: $_"
        Pop-Location
        exit 1
    }
    
    Pop-Location
    Write-Success "Client build complete"
}

# Build server components
function Build-Server {
    Write-Section "Building Server Components"
    
    Push-Location $SERVER_DIR
    
    try {
        Write-Info "Building basic server..."
        make basic
        Write-Success "Basic server compiled"
        
        Write-Info "Building enhanced server with assembly..."
        make enhanced
        Write-Success "Enhanced server compiled"
    }
    catch {
        Write-Error "Server build failed: $_"
        Pop-Location
        exit 1
    }
    
    Pop-Location
    Write-Success "Server build complete"
}

# Build GUI
function Build-GUI {
    Write-Section "Building GUI Components"
    
    Push-Location $GUI_DIR
    
    try {
        Write-Info "Building Win32 GUI with GCC..."
        make all
        Write-Success "GUI compiled"
    }
    catch {
        Write-Error "GUI build failed: $_"
        Pop-Location
        # Continue anyway
    }
    
    Pop-Location
}

# Build exploits
function Build-Exploits {
    Write-Section "Building Exploit Modules"
    
    Push-Location $EXPLOITS_DIR
    
    try {
        Write-Info "Building exploit modules..."
        make all
        Write-Success "Exploit modules compiled"
    }
    catch {
        Write-Error "Exploits build failed: $_"
        Pop-Location
        # Continue anyway
    }
    
    Pop-Location
}

# Generate CVE database
function Generate-CVEDatabase {
    Write-Section "Generating CVE Database"
    
    $scraper = Join-Path $EXPLOITS_DIR "mass_cve_scraper.py"
    
    if (-not (Test-Path $scraper)) {
        Write-Error "CVE scraper not found"
        return
    }
    
    try {
        Write-Info "Running CVE scraper..."
        python $scraper
        Write-Success "CVE database generated"
    }
    catch {
        Write-Error "CVE generation failed: $_"
        # Continue anyway
    }
}

# Install binaries
function Install-Binaries {
    Write-Section "Installing Binaries"
    
    if (-not (Test-Path $BIN_DIR)) {
        New-Item -ItemType Directory -Path $BIN_DIR | Out-Null
        Write-Info "Created bin directory"
    }
    
    # Copy client binaries
    $clientBuild = Join-Path $CLIENT_DIR "build"
    if (Test-Path $clientBuild) {
        Copy-Item "$clientBuild\*.exe" $BIN_DIR -Force -ErrorAction SilentlyContinue
        Copy-Item "$clientBuild\*.bin" $BIN_DIR -Force -ErrorAction SilentlyContinue
        Write-Success "Client binaries installed"
    }
    
    # Copy server binaries
    $serverBuild = Join-Path $SERVER_DIR "build"
    if (Test-Path $serverBuild) {
        Copy-Item "$serverBuild\*.exe" $BIN_DIR -Force -ErrorAction SilentlyContinue
        Write-Success "Server binaries installed"
    }
    
    # Copy GUI binaries
    $guiBuild = Join-Path $GUI_DIR "MoonlightC2-GUI.exe"
    if (Test-Path $guiBuild) {
        Copy-Item $guiBuild $BIN_DIR -Force -ErrorAction SilentlyContinue
        Write-Success "GUI binaries installed"
    }
    
    # Copy exploit modules
    $exploitsBuild = Join-Path $EXPLOITS_DIR "build"
    if (Test-Path $exploitsBuild) {
        $exploitsTarget = Join-Path $BIN_DIR "exploits"
        if (-not (Test-Path $exploitsTarget)) {
            New-Item -ItemType Directory -Path $exploitsTarget | Out-Null
        }
        Copy-Item "$exploitsBuild\*.exe" $exploitsTarget -Force -ErrorAction SilentlyContinue
        Write-Success "Exploit binaries installed"
    }
    
    Write-Success "Binary installation complete"
}

# Clean build artifacts
function Clean-Build {
    Write-Section "Cleaning Build Artifacts"
    
    Push-Location $CLIENT_DIR
    make clean 2>$null
    Pop-Location
    
    Push-Location $SERVER_DIR
    make clean 2>$null
    Pop-Location
    
    Push-Location $EXPLOITS_DIR
    make clean 2>$null
    Pop-Location
    
    if (Test-Path $BIN_DIR) {
        Remove-Item $BIN_DIR -Recurse -Force
        Write-Success "Bin directory cleaned"
    }
    
    Write-Success "Clean complete"
}

# Package release
function Package-Release {
    Write-Section "Packaging Release"
    
    $releaseDir = Join-Path $ROOT_DIR "release"
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $packageDir = Join-Path $releaseDir "moonlight-c2-$timestamp"
    
    if (-not (Test-Path $releaseDir)) {
        New-Item -ItemType Directory -Path $releaseDir | Out-Null
    }
    
    if (-not (Test-Path $packageDir)) {
        New-Item -ItemType Directory -Path $packageDir | Out-Null
    }
    
    # Copy binaries
    Copy-Item $BIN_DIR $packageDir -Recurse -Force
    
    # Copy documentation
    Copy-Item (Join-Path $ROOT_DIR "README.md") $packageDir -Force
    Copy-Item (Join-Path $ROOT_DIR "USAGE.md") $packageDir -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $ROOT_DIR "LICENSE") $packageDir -Force -ErrorAction SilentlyContinue
    
    # Create archive
    $archivePath = "$packageDir.zip"
    Compress-Archive -Path $packageDir -DestinationPath $archivePath -Force
    
    Write-Success "Release packaged: $archivePath"
}

# Show build summary
function Show-BuildSummary {
    Write-Section "Build Summary"
    
    Write-Info "Binaries located in: $BIN_DIR"
    
    if (Test-Path $BIN_DIR) {
        Write-Host "`nBuilt Components:" -ForegroundColor Yellow
        Get-ChildItem $BIN_DIR -Recurse -Include *.exe,*.bin | ForEach-Object {
            $size = [math]::Round($_.Length / 1KB, 2)
            Write-Host "  $($_.Name) ($size KB)" -ForegroundColor White
        }
    }
    
    Write-Host ""
    Write-Success "Build complete! Run enhanced server with: .\bin\moonlight-server-enhanced.exe"
}

# Main build function
function Build-All {
    $startTime = Get-Date
    
    Write-Host @"

███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗██╗     ██╗ ██████╗ ██╗  ██╗████████╗
████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║██║     ██║██╔════╝ ██║  ██║╚══██╔══╝
██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║██║     ██║██║  ███╗███████║   ██║   
██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║██║     ██║██║   ██║██╔══██║   ██║   
██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║███████╗██║╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                                                                              
                    C2 Framework Build System v2.0
                    With Assembly Enhancement
"@ -ForegroundColor Cyan
    
    Test-Prerequisites
    Build-Client
    Build-Server
    Build-GUI
    Build-Exploits
    Install-Binaries
    Show-BuildSummary
    
    $elapsed = (Get-Date) - $startTime
    Write-Host "`nTotal build time: $($elapsed.ToString('mm\:ss'))" -ForegroundColor Green
}

# Parse arguments
param(
    [switch]$Clean,
    [switch]$Client,
    [switch]$Server,
    [switch]$GUI,
    [switch]$Exploits,
    [switch]$Package,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Moonlight C2 Framework Build Script
====================================

Usage: .\Build-All.ps1 [options]

Options:
  -Clean      Clean all build artifacts
  -Client     Build only client components
  -Server     Build only server components
  -GUI        Build only GUI components
  -Exploits   Build only exploit modules
  -Package    Create release package
  -Help       Show this help message

Examples:
  .\Build-All.ps1              # Build everything
  .\Build-All.ps1 -Client      # Build only client
  .\Build-All.ps1 -Clean       # Clean all builds
  .\Build-All.ps1 -Package     # Build and package release

"@
    exit 0
}

if ($Clean) {
    Clean-Build
    exit 0
}

if ($Client) {
    Test-Prerequisites
    Build-Client
    exit 0
}

if ($Server) {
    Test-Prerequisites
    Build-Server
    exit 0
}

if ($GUI) {
    Test-Prerequisites
    Build-GUI
    exit 0
}

if ($Exploits) {
    Test-Prerequisites
    Build-Exploits
    exit 0
}

if ($Package) {
    Build-All
    Package-Release
    exit 0
}

# Default: build everything
Build-All
