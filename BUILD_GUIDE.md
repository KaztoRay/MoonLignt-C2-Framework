# Moonlight C2 Framework - Build Guide

Complete guide for building Moonlight C2 Framework on Windows with MinGW-w64 and NASM.

---

## Prerequisites Installation

### 1. MinGW-w64 (GCC for Windows)

**Download and Install:**

1. Download MinGW-w64 installer:
   - Visit: https://www.mingw-w64.org/downloads/
   - Or direct link: https://github.com/niXman/mingw-builds-binaries/releases
   - Choose: `x86_64-posix-seh` or `i686-posix-dwarf` (for 32-bit builds)

2. Extract to `C:\mingw64` (or your preferred location)

3. Add to PATH:
   ```powershell
   # Add MinGW bin directory to PATH
   $env:Path += ";C:\mingw64\bin"
   
   # Make permanent (requires admin)
   [Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
   ```

4. Verify installation:
   ```powershell
   gcc --version
   # Expected output: gcc (MinGW-W64...) 8.1.0 or newer
   ```

### 2. NASM (Netwide Assembler)

**Download and Install:**

1. Download NASM:
   - Visit: https://www.nasm.us/pub/nasm/releasebuilds/
   - Download latest stable (2.15+): `nasm-X.XX-installer-x64.exe`

2. Run installer and install to `C:\Program Files\NASM`

3. Add to PATH:
   ```powershell
   $env:Path += ";C:\Program Files\NASM"
   [Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
   ```

4. Verify installation:
   ```powershell
   nasm -v
   # Expected output: NASM version 2.15.xx or newer
   ```

### 3. GNU Make (Optional but Recommended)

**Option A: Install via Chocolatey**

```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Make
choco install make
```

**Option B: Use MinGW's mingw32-make**

MinGW-w64 includes `mingw32-make.exe`. Create an alias:

```powershell
# Create a 'make' wrapper script
@"
@echo off
mingw32-make %*
"@ | Out-File -Encoding ASCII C:\mingw64\bin\make.bat
```

**Option C: Manual Compilation (Without Make)**

See "Building Without Make" section below.

### 4. Python 3.8+ (For Exploit Generation)

1. Download from: https://www.python.org/downloads/
2. Install with "Add to PATH" option checked
3. Verify:
   ```powershell
   python --version
   ```

---

## Building the Framework

### Quick Build (PowerShell Script)

```powershell
# Build everything (recommended)
.\Build-All.ps1

# Build specific components
.\Build-All.ps1 -Client
.\Build-All.ps1 -Server
.\Build-All.ps1 -GUI
.\Build-All.ps1 -Exploits

# Clean build
.\Build-All.ps1 -Clean
```

### Manual Build Process

#### 1. Build Client (Enhanced Implant)

```powershell
cd client

# Create build directories
New-Item -ItemType Directory -Force -Path build\obj

# Compile assembly modules
nasm -f win32 stealth.asm -o build\obj\stealth.obj
nasm -f win32 syscalls.asm -o build\obj\syscalls.obj
nasm -f win32 network_asm.asm -o build\obj\network_asm.obj
nasm -f win32 monitoring.asm -o build\obj\monitoring.obj
nasm -f win32 control.asm -o build\obj\control.obj

# Compile C source
gcc -m32 -c implant_enhanced.c -o build\obj\implant_enhanced.o -Wall -O2
gcc -m32 -c monitoring_control.c -o build\obj\monitoring_control.o -Wall -O2

# Link everything
gcc -m32 -o build\moonlight-implant-enhanced.exe `
    build\obj\implant_enhanced.o `
    build\obj\monitoring_control.o `
    build\obj\stealth.obj `
    build\obj\syscalls.obj `
    build\obj\network_asm.obj `
    build\obj\monitoring.obj `
    build\obj\control.obj `
    -lws2_32 -ladvapi32 -lgdi32 -luser32 -s

# Build shellcode
nasm -f bin shellcode.asm -o build\shellcode.bin
```

#### 2. Build Server (Enhanced)

```powershell
cd server

# Create build directory
New-Item -ItemType Directory -Force -Path build\obj

# Compile assembly modules
nasm -f win32 network_asm.asm -o build\obj\network_asm.obj

# Compile C source
gcc -m32 -c main_enhanced.c -o build\obj\main_enhanced.o -Wall -O2 -DMAX_CLIENTS=100

# Link
gcc -m32 -o build\moonlight-server-enhanced.exe `
    build\obj\main_enhanced.o `
    build\obj\network_asm.obj `
    -lws2_32 -lpthread -s
```

#### 3. Build GUI (Win32 API)

```powershell
cd gui

# Compile GUI
gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0501 -mwindows `
    main.c -o MoonlightC2-GUI.exe `
    -lcomctl32 -lws2_32 -lgdi32 -lcomdlg32 -s
```

#### 4. Build Exploits

```powershell
cd exploits

# Create build directory
New-Item -ItemType Directory -Force -Path build

# Compile individual exploits
gcc -m32 ms08_067.c -o build\ms08-067.exe -lws2_32 -s
gcc -m32 ms17_010.c -o build\ms17-010.exe -lws2_32 -s
gcc -m32 ms03_026.c -o build\ms03-026.exe -lws2_32 -s
gcc -m32 ms10_015.c -o build\ms10-015.exe -ladvapi32 -s
gcc -m32 ms11_046.c -o build\ms11-046.exe -lws2_32 -s
gcc -m32 ms12_020.c -o build\ms12-020.exe -lws2_32 -s

# Compile all exploits
Get-ChildItem *.c | ForEach-Object {
    $name = $_.BaseName
    gcc -m32 $_.Name -o "build\$name.exe" -lws2_32 -ladvapi32 -s
}
```

---

## Building Without Make

If you don't have GNU Make installed, you can use these batch scripts:

### Build Client (build-client.bat)

```batch
@echo off
echo Building Enhanced Client...

if not exist build\obj mkdir build\obj

echo [*] Compiling assembly modules...
nasm -f win32 stealth.asm -o build\obj\stealth.obj
nasm -f win32 syscalls.asm -o build\obj\syscalls.obj
nasm -f win32 network_asm.asm -o build\obj\network_asm.obj
nasm -f win32 monitoring.asm -o build\obj\monitoring.obj
nasm -f win32 control.asm -o build\obj\control.obj

echo [*] Compiling C sources...
gcc -m32 -c implant_enhanced.c -o build\obj\implant_enhanced.o -Wall -O2
gcc -m32 -c monitoring_control.c -o build\obj\monitoring_control.o -Wall -O2

echo [*] Linking...
gcc -m32 -o build\moonlight-implant-enhanced.exe ^
    build\obj\implant_enhanced.o ^
    build\obj\monitoring_control.o ^
    build\obj\stealth.obj ^
    build\obj\syscalls.obj ^
    build\obj\network_asm.obj ^
    build\obj\monitoring.obj ^
    build\obj\control.obj ^
    -lws2_32 -ladvapi32 -lgdi32 -luser32 -s

echo [+] Client build complete!
```

### Build Server (build-server.bat)

```batch
@echo off
echo Building Enhanced Server...

if not exist build\obj mkdir build\obj

echo [*] Compiling assembly modules...
nasm -f win32 network_asm.asm -o build\obj\network_asm.obj

echo [*] Compiling C source...
gcc -m32 -c main_enhanced.c -o build\obj\main_enhanced.o -Wall -O2

echo [*] Linking...
gcc -m32 -o build\moonlight-server-enhanced.exe ^
    build\obj\main_enhanced.o ^
    build\obj\network_asm.obj ^
    -lws2_32 -lpthread -s

echo [+] Server build complete!
```

### Build GUI (build-gui.bat)

```batch
@echo off
echo Building GUI...

gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0501 -mwindows ^
    main.c -o MoonlightC2-GUI.exe ^
    -lcomctl32 -lws2_32 -lgdi32 -lcomdlg32 -s

echo [+] GUI build complete!
```

---

## Troubleshooting

### Common Build Errors

#### 1. "gcc: command not found"

**Problem**: MinGW not in PATH

**Solution**:
```powershell
# Add MinGW to PATH
$env:Path += ";C:\mingw64\bin"

# Verify
gcc --version
```

#### 2. "nasm: command not found"

**Problem**: NASM not in PATH

**Solution**:
```powershell
# Add NASM to PATH
$env:Path += ";C:\Program Files\NASM"

# Verify
nasm -v
```

#### 3. "undefined reference to `NtAllocateVirtualMemory`"

**Problem**: Missing syscall implementation or wrong linking order

**Solution**:
- Ensure `syscalls.obj` is compiled correctly
- Link assembly objects **after** C objects
- Verify NASM generated valid Win32 COFF objects (`-f win32`)

#### 4. "cannot find -lws2_32"

**Problem**: Missing Windows SDK libraries

**Solution**:
```powershell
# MinGW should include these. Verify installation:
gcc -print-search-dirs

# If missing, reinstall MinGW-w64 with full package
```

#### 5. "multiple definition of `_asm_rc4_crypt`"

**Problem**: Symbol defined in multiple object files

**Solution**:
- Check for duplicate assembly modules in link command
- Use `extern` declarations properly in headers
- Ensure each .asm module exports unique symbols

#### 6. "implant_enhanced.exe is not a valid Win32 application"

**Problem**: Linked as 64-bit instead of 32-bit

**Solution**:
```powershell
# Always use -m32 flag for GCC
gcc -m32 ...

# Use -f win32 for NASM
nasm -f win32 ...
```

### Verifying Build Output

```powershell
# Check if executable is 32-bit
Get-Item bin\moonlight-implant-enhanced.exe | Select-Object -ExpandProperty Length

# File should be around 100-150 KB

# Check dependencies
dumpbin /dependents bin\moonlight-implant-enhanced.exe
# Should show: KERNEL32.dll, WS2_32.dll, ADVAPI32.dll, etc.

# Test run (will try to connect to C2)
.\bin\moonlight-implant-enhanced.exe
```

---

## Build Configuration

### Compiler Flags Explained

**GCC Flags:**
- `-m32`: Compile for 32-bit (required for legacy Windows)
- `-Wall`: Enable all warnings
- `-O2`: Optimize for speed
- `-s`: Strip symbols (reduce binary size)
- `-mwindows`: GUI application (no console window)
- `-DWIN32`: Define Win32 platform macro
- `-D_WIN32_WINNT=0x0501`: Target Windows XP+ API

**NASM Flags:**
- `-f win32`: Output Win32 COFF object format
- `-o <file>`: Output file path

**Linker Flags:**
- `-lws2_32`: Link Winsock2 (networking)
- `-ladvapi32`: Advanced API (registry, services)
- `-lgdi32`: GDI (graphics, screenshots)
- `-luser32`: User interface API
- `-lcomctl32`: Common controls (GUI)
- `-lpthread`: POSIX threads (server)

### Optimization Levels

**Debug Build** (more verbose, easier debugging):
```powershell
gcc -m32 -g -O0 -Wall implant_enhanced.c -o implant-debug.exe
```

**Release Build** (optimized, smaller binary):
```powershell
gcc -m32 -O2 -s -Wall implant_enhanced.c -o implant-release.exe
```

**Maximum Optimization** (aggressive, may break some features):
```powershell
gcc -m32 -O3 -flto -s -Wall implant_enhanced.c -o implant-optimized.exe
```

---

## Cross-Compilation (Linux to Windows)

If building on Linux with MinGW cross-compiler:

### Install MinGW on Linux

```bash
# Debian/Ubuntu
sudo apt-get install mingw-w64 nasm

# Fedora/RHEL
sudo dnf install mingw64-gcc nasm

# Arch Linux
sudo pacman -S mingw-w64-gcc nasm
```

### Build Commands (Linux)

```bash
# Client
i686-w64-mingw32-gcc -m32 -o moonlight-implant.exe \
    implant_enhanced.c \
    stealth.obj syscalls.obj network_asm.obj \
    -lws2_32 -ladvapi32 -s

# Server
i686-w64-mingw32-gcc -m32 -o moonlight-server.exe \
    main_enhanced.c network_asm.obj \
    -lws2_32 -lpthread -s

# GUI
i686-w64-mingw32-gcc -m32 -mwindows -o MoonlightC2-GUI.exe \
    main.c \
    -lcomctl32 -lws2_32 -lgdi32 -s
```

---

## Binary Packaging

### Create Release Package

```powershell
# Build all components
.\Build-All.ps1

# Package release
.\Build-All.ps1 -Package

# Output: release\moonlight-c2-YYYYMMDD-HHMMSS.zip
```

### Manual Packaging

```powershell
# Create release directory
$release = "release\moonlight-c2-v2.0"
New-Item -ItemType Directory -Force -Path $release

# Copy binaries
Copy-Item bin\* $release\bin -Recurse

# Copy documentation
Copy-Item README.md, USAGE.md, COMMANDS.md, LICENSE $release

# Create archive
Compress-Archive -Path $release -DestinationPath "$release.zip"
```

---

## Development Tips

### Rapid Testing

```powershell
# Quick rebuild and test
cd client
make enhanced && ..\bin\moonlight-implant-enhanced.exe
```

### Debugging Assembly

```powershell
# Generate assembly listing with source
nasm -f win32 -l stealth.lst stealth.asm

# View listing
Get-Content stealth.lst
```

### Profiling Binary Size

```powershell
# Check section sizes
dumpbin /headers bin\moonlight-implant-enhanced.exe

# Identify large symbols
nm -S -C bin\moonlight-implant-enhanced.exe | Sort-Object -Descending
```

### Clean Build

```powershell
# Remove all build artifacts
Get-ChildItem -Path . -Include build -Recurse | Remove-Item -Recurse -Force
Get-ChildItem -Path . -Include *.exe,*.obj,*.o -Recurse | Remove-Item -Force
```

---

## Next Steps

After successful build:

1. **Test Components**:
   ```powershell
   # Start server
   .\bin\moonlight-server-enhanced.exe
   
   # In another terminal, run implant
   .\bin\moonlight-implant-enhanced.exe
   
   # Launch GUI
   .\bin\MoonlightC2-GUI.exe
   ```

2. **Read Documentation**:
   - [README.md](README.md) - Overview and features
   - [COMMANDS.md](COMMANDS.md) - Command reference
   - [ASSEMBLY_GUIDE.md](ASSEMBLY_GUIDE.md) - Assembly internals
   - [USAGE.md](USAGE.md) - Operational guide

3. **Customize**:
   - Edit `C2_SERVER` IP in `client/implant_enhanced.c`
   - Change encryption key in `ENCRYPTION_KEY` define
   - Modify port in server `DEFAULT_PORT`

4. **Deploy Responsibly**:
   - Only test on authorized systems
   - Follow ethical hacking guidelines
   - Document all activities

---

## Support

For build issues:
1. Check this guide first
2. Verify all prerequisites installed
3. Review error messages carefully
4. Check GitHub issues for similar problems

**Remember: This framework is for authorized security testing only!**

---

**Moonlight C2 Framework Build Guide**  
Version 2.0 | Build Date: 2025
