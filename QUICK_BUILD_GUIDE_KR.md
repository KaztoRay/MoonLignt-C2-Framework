# Moonlight C2 Framework - 빠른 빌드 가이드 (한국어)

## 📋 필수 요구사항

이 프로그램을 빌드하려면 다음 도구들이 필요합니다:

1. **MinGW-w64** (GCC C 컴파일러)
2. **NASM** (어셈블러)
3. **Make** (빌드 자동화 - 선택사항)

---

## 🚀 방법 1: Chocolatey를 사용한 자동 설치 (추천)

가장 쉽고 빠른 방법입니다.

### 단계 1: 관리자 권한으로 PowerShell 실행

1. 시작 메뉴에서 "PowerShell" 검색
2. **우클릭** → "관리자 권한으로 실행" 선택

### 단계 2: Chocolatey 설치

PowerShell에 다음 명령어를 복사하여 붙여넣고 Enter:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

### 단계 3: 빌드 도구 설치

Chocolatey 설치 완료 후 다음 명령어 실행:

```powershell
choco install mingw nasm make -y
```

설치 시간: 약 5-10분

### 단계 4: PowerShell 재시작

1. 현재 PowerShell 창 닫기
2. **일반 사용자 권한**으로 새 PowerShell 창 열기
3. 프로젝트 폴더로 이동:

```powershell
cd C:\Users\jeong\Desktop\MoonLignt-C2-Framework
```

### 단계 5: 빌드 실행

```powershell
.\Build-All.ps1
```

완료! 빌드된 파일들은 `bin\` 폴더에 생성됩니다.

---

## 🔧 방법 2: 수동 설치

Chocolatey를 사용하지 않으려면 수동으로 설치할 수 있습니다.

### MinGW-w64 설치

1. **다운로드**:
   - https://winlibs.com/ 방문
   - "Release versions" 섹션에서 최신 버전 다운로드
   - 예: `winlibs-x86_64-posix-seh-gcc-13.2.0-mingw-w64msvcrt-11.0.1-r5.zip`

2. **압축 해제**:
   - 다운로드한 ZIP 파일을 `C:\mingw64`에 압축 해제
   - 최종 경로: `C:\mingw64\bin\gcc.exe`

3. **PATH 환경변수 추가**:
   - 시작 메뉴 → "환경 변수" 검색
   - "시스템 환경 변수 편집" 클릭
   - "환경 변수" 버튼 클릭
   - "시스템 변수"에서 "Path" 선택 → "편집"
   - "새로 만들기" → `C:\mingw64\bin` 입력
   - "확인" 클릭

### NASM 설치

1. **다운로드**:
   - https://www.nasm.us/pub/nasm/releasebuilds/ 방문
   - 최신 버전의 `win64` 폴더 열기
   - `nasm-X.XX-win64.zip` 다운로드

2. **압축 해제**:
   - 다운로드한 ZIP 파일을 `C:\nasm`에 압축 해제
   - 최종 경로: `C:\nasm\nasm.exe`

3. **PATH 환경변수 추가**:
   - 위의 MinGW 설정과 동일한 방법으로
   - `C:\nasm` 경로 추가

### 설치 확인

새 PowerShell 창을 열고:

```powershell
gcc --version
nasm -v
```

버전 정보가 표시되면 설치 성공!

---

## 🏗️ 빌드 실행

### 전체 빌드

```powershell
.\Build-All.ps1
```

### 개별 컴포넌트 빌드

```powershell
# 클라이언트만 빌드
.\Build-All.ps1 -Client

# 서버만 빌드
.\Build-All.ps1 -Server

# GUI만 빌드
.\Build-All.ps1 -GUI

# Exploits만 빌드
.\Build-All.ps1 -Exploits
```

### 빌드 정리

```powershell
.\Build-All.ps1 -Clean
```

---

## 📁 빌드 결과

빌드가 성공하면 다음 파일들이 생성됩니다:

```
bin/
├── moonlight-implant-enhanced.exe    # 클라이언트 (타겟 시스템용)
├── moonlight-server-enhanced.exe     # C2 서버
├── MoonlightC2-GUI.exe               # GUI 인터페이스
├── shellcode.bin                     # 쉘코드
└── exploits/                         # Exploit 모듈들
    ├── ms08-067.exe
    ├── ms17-010.exe
    ├── ms03-026.exe
    └── ... (더 많은 exploits)
```

---

## 🚀 실행 방법

### 1. 서버 시작

```powershell
.\bin\moonlight-server-enhanced.exe
```

기본 포트: 4444

### 2. GUI 실행 (선택사항)

```powershell
.\bin\MoonlightC2-GUI.exe
```

### 3. 클라이언트 배포

타겟 시스템에서:

```powershell
.\bin\moonlight-implant-enhanced.exe
```

**주의**: 서버 IP는 `client/implant_enhanced.c` 파일에서 수정해야 합니다:

```c
#define C2_SERVER "192.168.1.100"  // 여기를 당신의 서버 IP로 변경
```

---

## ⚠️ 문제 해결

### "gcc: command not found" 오류

**원인**: MinGW가 PATH에 없음

**해결**:
1. MinGW가 설치되어 있는지 확인: `C:\mingw64\bin\gcc.exe`
2. PATH 환경변수에 `C:\mingw64\bin` 추가
3. **새로운** PowerShell 창 열기 (중요!)

### "nasm: command not found" 오류

**원인**: NASM이 PATH에 없음

**해결**:
1. NASM이 설치되어 있는지 확인: `C:\nasm\nasm.exe`
2. PATH 환경변수에 `C:\nasm` 추가
3. **새로운** PowerShell 창 열기 (중요!)

### "undefined reference" 링킹 오류

**원인**: 어셈블리 파일이 제대로 컴파일되지 않음

**해결**:
```powershell
.\Build-All.ps1 -Clean
.\Build-All.ps1
```

### 32비트 빌드 오류

일부 시스템에서는 32비트 라이브러리가 없을 수 있습니다.

**해결**: 64비트로 빌드하려면 Makefile에서 `-m32` 플래그 제거

---

## 📖 추가 문서

- **README.md** - 프로젝트 개요
- **BUILD_GUIDE.md** - 상세 빌드 가이드 (영문)
- **COMMANDS.md** - 명령어 레퍼런스
- **ASSEMBLY_GUIDE.md** - 어셈블리 모듈 설명

---

## ⚠️ 법적 고지

이 프레임워크는 **교육 및 승인된 보안 테스트 목적**으로만 사용해야 합니다.

- ✅ 본인 소유 시스템 테스트
- ✅ 서면 승인받은 침투 테스트
- ✅ 보안 연구 및 교육
- ❌ 무단 시스템 접근
- ❌ 악의적 사용

**불법 사용으로 인한 모든 책임은 사용자에게 있습니다.**

---

## 🆘 도움말

빌드 중 문제가 발생하면:

1. 이 가이드의 문제 해결 섹션 확인
2. BUILD_GUIDE.md의 상세 가이드 참조
3. 빌드 도구가 올바르게 설치되었는지 확인:
   ```powershell
   gcc --version
   nasm -v
   ```

**Happy Building! 🚀**
