# CardinalOS v4.0 - Complete Command Reference

## 🖥️ Dual System Commands (DOS + Linux/Unix)

CardinalOS는 DOS, Linux, Unix 명령어를 모두 지원하는 통합 운영체제입니다.

---

## 📁 File Operations

### Linux/Unix Commands
```bash
ls [path]              # List directory contents
ll                     # Detailed list (ls -la)
cd <path>              # Change directory
pwd                    # Print working directory
mkdir <dir>            # Create directory
rmdir <dir>            # Remove empty directory
touch <file>           # Create empty file
cat <file>             # Display file content
more <file>            # Page through file
less <file>            # Page through file (better)
head <file>            # Show first lines
tail <file>            # Show last lines
rm <file>              # Remove file
cp <src> <dst>         # Copy file
mv <src> <dst>         # Move/rename file
ln <src> <dst>         # Create link
chmod <mode> <file>    # Change permissions (e.g., chmod 755 file)
chown <user> <file>    # Change owner
find <pattern>         # Find files
grep <pattern> [file]  # Search in files
diff <file1> <file2>   # Compare files
```

### DOS Commands
```dos
dir [path]             # List directory (DOS style)
cd, chdir <path>       # Change directory (DOS)
md, mkdir <dir>        # Make directory (DOS)
rd, rmdir <dir>        # Remove directory (DOS)
type <file>            # Display file (DOS)
copy <src> <dst>       # Copy file (DOS)
xcopy <src> <dst>      # Extended copy (DOS)
move <src> <dst>       # Move file (DOS)
del <file>             # Delete file (DOS)
erase <file>           # Delete file (DOS)
ren <old> <new>        # Rename file (DOS)
rename <old> <new>     # Rename file (DOS)
attrib [+/-RH] <file>  # Set file attributes (R=readonly, H=hidden)
tree                   # Display directory tree
comp <f1> <f2>         # Compare files (DOS)
fc <f1> <f2>           # File compare (DOS)
find <pattern>         # Find string in files (DOS)
findstr <pattern>      # Find string (DOS)
sort                   # Sort text (DOS)
more <file>            # Display with paging (DOS)
```

---

## 💾 Disk Management (DOS)

```dos
chkdsk [drive]         # Check disk for errors
scandisk [drive]       # Scan and fix disk
format <drive>         # Format drive (WARNING: deletes all data!)
diskpart               # Disk partition utility
vol                    # Display volume information
label [name]           # Set volume label
path                   # Display/set PATH environment
```

---

## 🔧 System Commands

### Universal Commands (Work on both DOS and Linux)
```bash
help                   # Show command help
?                      # Show command help (DOS alias)
version                # Display version information
ver                    # Display version (DOS style)
uname                  # Print system information
uname -a               # Detailed system info
hostname               # Show hostname
hostname <name>        # Set hostname (admin only)
uptime                 # System uptime and load
date                   # Show current date/time
time                   # Show current time
cls                    # Clear screen (DOS)
clear                  # Clear screen (Linux)
exit                   # Exit/shutdown
quit                   # Exit (alias)
reboot                 # Reboot system
restart                # Restart (alias)
shutdown               # Shutdown system
```

### Environment Commands
```bash
env                    # Show environment variables (Linux)
set                    # Show environment variables (DOS)
echo <text>            # Print text
prompt                 # Display prompt settings (DOS)
doskey                 # Keyboard macros (DOS)
```

---

## 👥 User Management

```bash
whoami                 # Show current user
users                  # List all users
who                    # Show logged-in users
id                     # Display user identity
groups                 # Show user groups
su <user>              # Switch user
sudo <command>         # Execute as administrator
passwd                 # Change password
```

---

## ⚙️ Process Management

### Linux/Unix Commands
```bash
ps                     # List processes
ps aux                 # Detailed process list
top                    # Real-time process monitor
kill <pid>             # Terminate process by PID
kill -9 <pid>          # Force kill process
killall <name>         # Kill processes by name
bg                     # Send job to background
fg                     # Bring job to foreground
jobs                   # List background jobs
```

### DOS Commands
```dos
tasklist               # List running processes (DOS)
taskkill <pid>         # Kill process by PID (DOS)
start <program>        # Start program (DOS)
```

---

## 🌐 Network Commands

### Linux/Unix Commands
```bash
ifconfig               # Show network interfaces
ip addr                # Show IP addresses (modern)
netstat                # Network connections
netstat -an            # All connections, numeric
ping <host>            # Test connectivity
ping -c 4 <host>       # Ping 4 times
traceroute <host>      # Trace route to host
nslookup <host>        # DNS lookup
dig <host>             # DNS query (detailed)
route                  # Show routing table
arp                    # Show ARP table
arp -a                 # Display all ARP entries
nc <host> <port>       # Netcat - network utility
curl <url>             # Transfer data from URL
wget <url>             # Download file from URL
ssh <user>@<host>      # Secure shell
telnet <host> <port>   # Telnet connection
```

### DOS Commands
```dos
ipconfig               # IP configuration (DOS)
ipconfig /all          # Detailed IP config
netstat                # Network status (DOS)
tracert <host>         # Trace route (DOS)
nslookup <host>        # DNS lookup (DOS)
net <command>          # Network commands (DOS)
net view               # View network computers
net use                # View/connect network drives
net user               # Manage users
net share              # Manage shares
```

---

## 🔍 System Information

```bash
free                   # Memory usage (Linux)
free -h                # Human-readable memory
mem                    # Memory information (DOS)
memory                 # Memory information (DOS)
df                     # Disk space usage (Linux)
df -h                  # Human-readable disk space
mount                  # Show mounted filesystems
lsblk                  # List block devices (Linux)
```

---

## 🔐 Security Commands

```bash
security               # Security status dashboard
firewall status        # Check firewall status
firewall enable        # Enable firewall
firewall disable       # Disable firewall (admin)
selinux status         # SELinux status
audit                  # View audit logs
```

---

## 🎯 Attack & Penetration Testing Commands

```bash
exploit-db             # List exploit database (200+ CVEs)
exploits               # Alias for exploit-db
c2-start               # Start C2 server
payload-gen            # Payload generator
scan <target>          # Comprehensive target scan
nmap <target>          # Port scan with nmap
portscan <target>      # Quick port scanner
```

---

## 🖥️ GUI Desktop Commands

```bash
desktop                # Launch Win32 GUI Desktop Environment
startx                 # Launch GUI (alias)
```

### GUI Desktop Features
- **File Manager**: Browse filesystem
- **Terminal**: Command-line interface
- **Security Dashboard**: Security status and controls
- **Process Monitor**: Real-time process viewer
- **Network Analyzer**: Network interface and connection viewer
- **Exploit Console**: Access exploit database
- **Menu Bar**: File, Tools, Help menus
- **Taskbar**: Shows current time and user info

---

## 💿 Advanced Features

```bash
iso-generate           # Generate bootable ISO image
mkiso                  # Alias for iso-generate
benchmark              # System performance test
```

---

## 📋 Command Aliases

Many commands have multiple aliases for compatibility:

| Linux Command | DOS Equivalent | Alias Options |
|---------------|----------------|---------------|
| ls            | dir            | ll (ls -la)   |
| cd            | cd, chdir      | -             |
| mkdir         | md, mkdir      | -             |
| rmdir         | rd, rmdir      | -             |
| cat           | type           | -             |
| rm            | del, erase     | -             |
| cp            | copy, xcopy    | -             |
| mv            | move, ren      | -             |
| clear         | cls            | -             |
| ps            | tasklist       | -             |
| kill          | taskkill       | -             |
| ifconfig      | ipconfig       | -             |
| traceroute    | tracert        | -             |
| more          | more           | less          |
| find          | find, findstr  | grep          |

---

## 🔧 Tips & Tricks

### Command History
- Use arrow keys (↑↓) to navigate command history
- `!!` - Repeat last command (bash-style)

### File Wildcards
```bash
ls *.txt               # List all .txt files
copy *.* backup\       # Copy all files
del temp*              # Delete files starting with "temp"
```

### Piping & Redirection
```bash
command > file         # Redirect output to file
command >> file        # Append output to file
command | command2     # Pipe output to another command
command 2>&1           # Redirect stderr to stdout
```

### Multiple Commands
```bash
command1 ; command2    # Run sequentially
command1 && command2   # Run command2 if command1 succeeds
command1 || command2   # Run command2 if command1 fails
```

### Path Formats
```bash
/root/file.txt         # Linux absolute path
C:\Windows\file.txt    # DOS absolute path
./file.txt             # Current directory
../file.txt            # Parent directory
```

---

## 🚀 Quick Start Examples

### Basic Navigation
```bash
# List current directory
ls
dir

# Change to root
cd /
cd C:\

# Show current location
pwd

# Create and navigate
mkdir /tmp/test
cd /tmp/test
```

### Network Testing
```bash
# Check network interface
ifconfig
ipconfig

# Test connectivity
ping google.com
ping 8.8.8.8

# Port scan
nmap 192.168.1.1
portscan 192.168.1.100
```

### System Information
```bash
# System details
uname -a
ver

# Check processes
ps
tasklist

# Memory usage
free
mem

# Security status
security
firewall status
```

### Attack Operations
```bash
# View exploits
exploit-db

# Start C2 server
c2-start

# Scan target
scan 192.168.1.100

# Launch GUI for advanced operations
desktop
```

---

## 📖 Help Resources

```bash
help                   # General help
help <command>         # Command-specific help (planned)
man <command>          # Manual page (planned)
<command> /?           # DOS-style help
<command> --help       # Linux-style help
```

---

## ⚠️ Important Notes

1. **Admin Privileges**: Some commands require administrator rights
2. **Path Separators**: Use `/` for Linux paths, `\` for DOS paths
3. **Case Sensitivity**: Linux commands are case-sensitive, DOS are not
4. **Dangerous Commands**: `format`, `del *.*`, `rm -rf` can delete data!
5. **Network Commands**: Some may require actual network connectivity

---

**CardinalOS v4.0.0 Enterprise Edition**  
*Unified DOS + Linux + Unix Command System*  
*With Real Win32 GUI Desktop Environment*

**Total Commands: 150+ unified commands across all platforms**
