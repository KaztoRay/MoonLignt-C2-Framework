# CardinalOS v4.0 - Quick Start Guide

## 🚀 가장 빠른 실행 방법 (Windows)

### 1단계: 즉시 실행

```powershell
# CardinalOS 디렉터리에서
.\cardinalos_v4.exe
```

**그게 전부입니다!** 추가 설치 없이 바로 사용 가능합니다.

---

## 📋 주요 명령어 테스트

CardinalOS가 실행되면 다음 명령어들을 테스트해보세요:

### 시스템 정보
```bash
version              # 버전 정보
uname -a             # 시스템 정보
hostname             # 호스트명
uptime               # 가동 시간
whoami               # 현재 사용자
```

### 파일 시스템
```bash
ls /                 # 루트 디렉터리 목록
cd /etc              # 디렉터리 이동
pwd                  # 현재 위치
cat /etc/hostname    # 파일 내용 보기
mkdir /tmp/test      # 디렉터리 생성
touch /tmp/test.txt  # 파일 생성
```

### 네트워크
```bash
ifconfig             # 네트워크 인터페이스
netstat              # 네트워크 연결
ping 8.8.8.8         # 핑 테스트
traceroute google.com # 경로 추적
nmap 192.168.1.1     # 포트 스캔
portscan 192.168.1.1 # 빠른 포트 스캔
```

### 프로세스 관리
```bash
ps                   # 프로세스 목록
users                # 사용자 목록
free                 # 메모리 사용량
df                   # 디스크 사용량
mount                # 마운트된 파일시스템
```

### 보안
```bash
security             # 보안 상태
firewall status      # 방화벽 상태
firewall enable      # 방화벽 활성화
exploit-db           # 익스플로잇 데이터베이스
```

### 공격 도구
```bash
exploit-db           # 익스플로잇 목록
c2-start             # C2 서버 시작
payload-gen          # 페이로드 생성
scan 192.168.1.1     # 타겟 스캔
```

### 고급 기능
```bash
desktop              # GUI 데스크톱 모드
iso-generate         # ISO 이미지 생성
```

### 기타
```bash
help                 # 모든 명령어 보기
date                 # 날짜/시간
env                  # 환경 변수
echo Hello World     # 텍스트 출력
clear                # 화면 지우기
```

---

## 🔥 전체 기능 테스트 시나리오

CardinalOS를 완전히 테스트하려면:

```bash
# 1. 시스템 확인
version
security
uptime

# 2. 파일시스템 탐색
ls /
cd /etc
cat /etc/hostname
cat /etc/hosts
cd /cardinal
ls

# 3. 사용자 확인
whoami
users

# 4. 네트워크 테스트
ifconfig
netstat
ping 8.8.8.8

# 5. 프로세스 확인
ps
free
df

# 6. 보안 기능
security
firewall status

# 7. 공격 도구
exploit-db
nmap 192.168.1.1

# 8. 고급 기능
desktop              # GUI 모드 (아무 키나 눌러서 나가기)
iso-generate         # ISO 생성 (시뮬레이션)

# 9. 종료
exit
```

---

## 💿 ISO로 QEMU 테스트 (선택사항)

QEMU가 설치되어 있다면:

### Windows PowerShell
```powershell
# QEMU 설치 확인
qemu-system-x86_64 --version

# CardinalOS ISO 생성은 Linux/WSL 필요
# 하지만 .exe를 직접 실행할 수 있습니다!
.\cardinalos_v4.exe
```

### QEMU 설치 (선택)
```powershell
# Chocolatey로 설치
choco install qemu -y

# 또는 직접 다운로드
# https://qemu.weilnetz.de/w64/
```

### ISO 테스트 (WSL/Linux에서 ISO 생성 후)
```bash
qemu-system-x86_64 -cdrom CardinalOS-*.iso -m 512M -boot d
```

---

## 🎯 핵심 포인트

### ✅ 바로 사용 가능
- `cardinalos_v4.exe` 실행만으로 모든 기능 사용
- 추가 설치 불필요
- Windows에서 네이티브 실행

### ✅ 200+ 명령어
- Linux 명령어 (ls, cd, cat, ps, ifconfig, netstat, etc.)
- DOS 명령어 (dir, chdir, type, tasklist, etc.)
- 공격 도구 (nmap, exploit-db, c2-start, etc.)

### ✅ 고급 기능
- GUI 데스크톱 모드
- ISO 이미지 생성
- C2 프레임워크
- 익스플로잇 데이터베이스

---

## 📚 추가 문서

- **CHANGELOG_V4.md** - 전체 변경사항
- **CARDINALOS_V4_GUIDE.md** - 상세 사용 가이드
- **QEMU_GUIDE.md** - QEMU 및 가상화 가이드

---

## 🐛 문제 해결

### "명령어가 안 먹혀요"
→ `help`를 입력해서 사용 가능한 명령어 목록 확인

### "Permission denied"
→ 관리자 권한이 필요한 명령어입니다 (현재 root로 로그인되어 있어야 함)

### "실행이 안돼요"
→ Windows Defender가 차단했을 수 있습니다. 예외로 추가하세요.

---

## 🎓 학습 경로

1. **초급**: 기본 명령어 (ls, cd, cat, help)
2. **중급**: 네트워크 명령어 (ifconfig, netstat, ping)
3. **고급**: 공격 도구 (exploit-db, nmap, c2-start)
4. **전문가**: GUI 모드, ISO 생성, 실제 배포

---

**즐거운 해킹 되세요! 🎯**

CardinalOS v4.0.0 Enterprise Edition
