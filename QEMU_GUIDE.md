# CardinalOS QEMU Testing Guide

## QEMU 설치

### Windows에서 QEMU 설치

#### 방법 1: QEMU 공식 설치 (권장)

1. **다운로드**
   ```
   https://qemu.weilnetz.de/w64/
   ```
   최신 버전 다운로드 (예: qemu-w64-setup-20240423.exe)

2. **설치**
   - 다운로드한 설치 파일 실행
   - 기본 설정으로 설치 (`C:\Program Files\qemu`)
   - PATH에 자동 추가됨

3. **설치 확인**
   ```powershell
   qemu-system-x86_64 --version
   ```

#### 방법 2: Chocolatey 사용

```powershell
# Chocolatey가 없다면 먼저 설치
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# QEMU 설치
choco install qemu -y

# 설치 확인
qemu-system-x86_64 --version
```

#### 방법 3: MSYS2/MinGW 사용

```bash
# MSYS2 터미널에서
pacman -S mingw-w64-x86_64-qemu
```

---

## CardinalOS ISO 생성 (Linux/WSL 필요)

### WSL2 설치 (Windows에서 Linux 환경)

```powershell
# Windows PowerShell (관리자)
wsl --install

# 재부팅 후 WSL에서
sudo apt update
sudo apt install gcc grub-pc-bin grub-efi-amd64-bin xorriso mtools python3
```

### ISO 생성 (WSL/Linux)

```bash
# CardinalOS 디렉터리로 이동
cd /mnt/c/Users/jeong/Desktop/Cardinal-C2-Framework

# 빌드 스크립트 실행 권한 부여
chmod +x build.sh

# ISO 생성
./build.sh
```

---

## CardinalOS 실행 방법

### 방법 1: Windows에서 직접 실행 (.exe)

```powershell
# PowerShell에서
.\cardinalos_v4.exe
```

**장점:**
- 가장 빠르고 간단
- 추가 설치 불필요
- Windows 네이티브 실행

**단점:**
- Windows API 의존
- 실제 부팅 환경이 아님

---

### 방법 2: QEMU로 ISO 부팅 (실제 OS처럼)

#### Windows PowerShell에서

```powershell
# ISO가 있는 경우
qemu-system-x86_64 -cdrom CardinalOS-v4.0.0-*.iso -m 512M -boot d -serial stdio

# 더 많은 리소스로 실행
qemu-system-x86_64 `
  -cdrom CardinalOS-v4.0.0-*.iso `
  -m 1024M `
  -smp 2 `
  -boot d `
  -serial stdio `
  -vga std

# 네트워크 포함
qemu-system-x86_64 `
  -cdrom CardinalOS-v4.0.0-*.iso `
  -m 512M `
  -boot d `
  -netdev user,id=net0 `
  -device e1000,netdev=net0 `
  -serial stdio
```

#### Linux/WSL에서

```bash
# 기본 실행
qemu-system-x86_64 -cdrom CardinalOS-v4.0.0-*.iso -m 512M -boot d

# GUI와 함께 실행
qemu-system-x86_64 \
  -cdrom CardinalOS-*.iso \
  -m 1024M \
  -smp 4 \
  -boot d \
  -display gtk \
  -serial stdio

# 하드디스크 이미지 생성 및 사용
qemu-img create -f qcow2 cardinalos.qcow2 10G
qemu-system-x86_64 \
  -cdrom CardinalOS-*.iso \
  -hda cardinalos.qcow2 \
  -m 1024M \
  -boot d
```

**QEMU 키보드 단축키:**
- `Ctrl+Alt+F` - 전체화면 전환
- `Ctrl+Alt+G` - 마우스 캡처 해제
- `Ctrl+Alt+2` - QEMU 모니터
- `Ctrl+Alt+1` - 게스트 화면으로 돌아가기
- `Ctrl+A` then `X` - 종료 (Serial 모드)

---

### 방법 3: VirtualBox (가상 머신)

#### VirtualBox 설치

```
https://www.virtualbox.org/wiki/Downloads
```

#### GUI로 VM 생성

1. **VirtualBox 열기** → "새로 만들기"

2. **설정:**
   - 이름: CardinalOS
   - 종류: Linux
   - 버전: Other Linux (64-bit)
   - 메모리: 512 MB
   - 하드 디스크: 생성 (10 GB VDI)

3. **ISO 마운트:**
   - VM 선택 → 설정 → 저장소
   - "컨트롤러: IDE" → 빈 디스크 아이콘 클릭
   - 오른쪽 디스크 아이콘 → "디스크 파일 선택"
   - CardinalOS ISO 선택

4. **시작:** VM 선택 → 시작

#### 명령줄로 VM 생성

```powershell
# Windows PowerShell
$ISO = (Get-ChildItem CardinalOS-*.iso | Select-Object -First 1).FullName

VBoxManage createvm --name CardinalOS --ostype Linux26_64 --register
VBoxManage modifyvm CardinalOS --memory 512 --vram 128 --cpus 2
VBoxManage createhd --filename "$HOME\VirtualBox VMs\CardinalOS\CardinalOS.vdi" --size 10240
VBoxManage storagectl CardinalOS --name SATA --add sata --controller IntelAhci
VBoxManage storageattach CardinalOS --storagectl SATA --port 0 --device 0 --type hdd --medium "$HOME\VirtualBox VMs\CardinalOS\CardinalOS.vdi"
VBoxManage storagectl CardinalOS --name IDE --add ide
VBoxManage storageattach CardinalOS --storagectl IDE --port 0 --device 0 --type dvddrive --medium $ISO
VBoxManage modifyvm CardinalOS --boot1 dvd --boot2 disk
VBoxManage startvm CardinalOS
```

```bash
# Linux/WSL
ISO=$(ls CardinalOS-*.iso | head -n 1)

VBoxManage createvm --name CardinalOS --ostype Linux26_64 --register
VBoxManage modifyvm CardinalOS --memory 512 --vram 128 --cpus 2
VBoxManage createhd --filename "$HOME/VirtualBox VMs/CardinalOS/CardinalOS.vdi" --size 10240
VBoxManage storagectl CardinalOS --name SATA --add sata --controller IntelAhci
VBoxManage storageattach CardinalOS --storagectl SATA --port 0 --device 0 --type hdd --medium "$HOME/VirtualBox VMs/CardinalOS/CardinalOS.vdi"
VBoxManage storagectl CardinalOS --name IDE --add ide
VBoxManage storageattach CardinalOS --storagectl IDE --port 0 --device 0 --type dvddrive --medium "$ISO"
VBoxManage modifyvm CardinalOS --boot1 dvd --boot2 disk
VBoxManage startvm CardinalOS
```

---

### 방법 4: VMware (가상 머신)

#### VMware Workstation Player (무료)

```
https://www.vmware.com/products/workstation-player.html
```

#### VM 생성

1. **VMware Player 열기** → "Create a New Virtual Machine"

2. **설정:**
   - Installer disc image (iso): CardinalOS ISO 선택
   - Guest OS: Linux → Other Linux 5.x kernel 64-bit
   - 이름: CardinalOS
   - 디스크 크기: 10 GB
   - 메모리: 512 MB

3. **시작:** Play virtual machine

---

## 성능 최적화 옵션

### QEMU 최적화 플래그

```bash
qemu-system-x86_64 \
  -cdrom CardinalOS-*.iso \
  -m 1024M \
  -smp 4,cores=2,threads=2 \
  -cpu host \
  -enable-kvm \              # Linux only (KVM 가속)
  -machine accel=kvm \       # Linux only
  -vga virtio \
  -display sdl,gl=on \
  -boot d
```

### Windows에서 HAXM 사용 (Intel CPU)

```powershell
# HAXM 다운로드 및 설치
# https://github.com/intel/haxm/releases

# HAXM으로 QEMU 실행
qemu-system-x86_64 -cdrom CardinalOS-*.iso -m 512M -accel hax
```

---

## 실제 하드웨어에 설치

### USB 부팅 디스크 만들기

#### Windows - Rufus 사용 (권장)

1. **Rufus 다운로드**
   ```
   https://rufus.ie/
   ```

2. **USB에 쓰기**
   - USB 드라이브 연결 (8GB 이상)
   - Rufus 실행
   - 장치: USB 드라이브 선택
   - 부트 방식: ISO/DD 이미지
   - "선택" → CardinalOS ISO
   - 파티션 방식: MBR (BIOS) 또는 GPT (UEFI)
   - "시작" 클릭

#### Windows - PowerShell

```powershell
# Win32 Disk Imager 다운로드 필요
# https://sourceforge.net/projects/win32diskimager/

# 또는 dd for windows
# http://www.chrysocome.net/dd

# USB 장치 확인
Get-Disk

# ISO 쓰기 (X는 USB 디스크 번호)
# 주의: 모든 데이터가 삭제됩니다!
# dd if=CardinalOS-*.iso of=\\.\PhysicalDriveX bs=4M
```

#### Linux

```bash
# USB 장치 확인
lsblk

# ISO 쓰기 (sdX는 USB 장치, 예: sdb)
# 주의: 모든 데이터가 삭제됩니다!
sudo dd if=CardinalOS-*.iso of=/dev/sdX bs=4M status=progress
sudo sync
```

### 실제 PC에서 부팅

1. USB 연결
2. PC 재부팅
3. BIOS/UEFI 진입 (F2, F12, DEL, ESC 키)
4. Boot Order에서 USB를 첫 번째로 설정
5. 저장 후 재부팅
6. GRUB 메뉴에서 CardinalOS 선택

---

## 테스트 시나리오

### 빠른 테스트 (Windows .exe)

```powershell
# 1. 실행
.\cardinalos_v4.exe

# 2. 명령어 테스트
help
version
ls /
cd /etc
cat /etc/hostname
ifconfig
netstat
ps
security
whoami
users
```

### 완전한 테스트 (QEMU ISO)

```bash
# 1. QEMU로 부팅
qemu-system-x86_64 -cdrom CardinalOS-*.iso -m 512M -boot d -serial stdio

# 2. GRUB에서 "CardinalOS v4.0.0 - Normal Boot" 선택

# 3. 부팅 후 명령어 테스트
help
ifconfig
ping 8.8.8.8
nmap 192.168.1.1
exploit-db
c2-start
desktop
iso-generate
```

---

## 트러블슈팅

### QEMU 실행 시 오류

**오류:** `qemu-system-x86_64: command not found`
- **해결:** PATH에 QEMU 추가
  ```powershell
  $env:Path += ";C:\Program Files\qemu"
  ```

**오류:** `Could not open boot device`
- **해결:** ISO 파일 경로 확인, 절대 경로 사용

**오류:** `KVM not available`
- **해결:** Windows에서는 정상, Linux에서는 KVM 설치 필요

### ISO 생성 실패

**오류:** `grub-mkrescue: command not found`
- **해결:** WSL/Linux에서 GRUB 설치
  ```bash
  sudo apt install grub-pc-bin grub-efi-amd64-bin
  ```

**오류:** `xorriso: command not found`
- **해결:** xorriso 설치
  ```bash
  sudo apt install xorriso
  ```

### VirtualBox 문제

**오류:** `VT-x is disabled`
- **해결:** BIOS에서 가상화 기술 활성화 (Intel VT-x / AMD-V)

**오류:** `ISO not booting`
- **해결:** 
  - Boot Order 확인 (IDE CD를 첫 번째로)
  - ISO를 다시 마운트

---

## 권장 테스트 순서

1. ✅ **Windows .exe 실행** (가장 빠름, 기본 기능 테스트)
   ```powershell
   .\cardinalos_v4.exe
   ```

2. ✅ **QEMU로 .exe 실행** (Linux 환경 시뮬레이션)
   ```bash
   qemu-system-x86_64 -kernel cardinalos_v4.exe -m 512M
   ```

3. ✅ **ISO 생성 및 QEMU 부팅** (완전한 부팅 경험)
   ```bash
   ./build.sh
   qemu-system-x86_64 -cdrom CardinalOS-*.iso -m 512M -boot d
   ```

4. ✅ **VirtualBox/VMware 테스트** (가상 머신 환경)

5. ⚠️  **실제 하드웨어 테스트** (프로덕션 환경, 주의 필요)

---

## 자동화 스크립트

### 빠른 실행 스크립트 (PowerShell)

```powershell
# quick_test.ps1
param(
    [switch]$Exe,
    [switch]$Qemu,
    [switch]$VirtualBox
)

if ($Exe -or (!$Qemu -and !$VirtualBox)) {
    Write-Host "Starting CardinalOS .exe..." -ForegroundColor Cyan
    .\cardinalos_v4.exe
}

if ($Qemu) {
    $iso = Get-ChildItem CardinalOS-*.iso | Select-Object -First 1
    if ($iso) {
        Write-Host "Starting QEMU with $($iso.Name)..." -ForegroundColor Cyan
        qemu-system-x86_64 -cdrom $iso.FullName -m 512M -boot d -serial stdio
    } else {
        Write-Host "ISO not found!" -ForegroundColor Red
    }
}

if ($VirtualBox) {
    $iso = Get-ChildItem CardinalOS-*.iso | Select-Object -First 1
    if ($iso) {
        Write-Host "Starting VirtualBox with $($iso.Name)..." -ForegroundColor Cyan
        # VirtualBox 시작 코드
    } else {
        Write-Host "ISO not found!" -ForegroundColor Red
    }
}
```

**사용법:**
```powershell
# .exe 실행
.\quick_test.ps1 -Exe

# QEMU로 ISO 실행
.\quick_test.ps1 -Qemu

# VirtualBox로 실행
.\quick_test.ps1 -VirtualBox
```

---

## 추가 리소스

- **QEMU 문서:** https://www.qemu.org/docs/master/
- **VirtualBox 문서:** https://www.virtualbox.org/manual/
- **GRUB 문서:** https://www.gnu.org/software/grub/manual/
- **CardinalOS GitHub:** https://github.com/KaztoRay/MoonLignt-C2-Framework

---

**Happy Testing! 🚀**
