// ============================================================================
// 로그 윈도우 생성
// ============================================================================
void CreateLogWindow(HWND hwnd) {
    g_hEditLog = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
                                WS_CHILD | WS_VISIBLE | WS_VSCROLL | 
                                ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                10, 420, 1360, 300,
                                hwnd, (HMENU)IDC_EDIT_LOG,
                                GetModuleHandle(NULL), NULL);
    
    SendMessage(g_hEditLog, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);
}

// ============================================================================
// 명령 패널 생성
// ============================================================================
void CreateCommandPanel(HWND hwnd) {
    // 명령 입력창
    g_hEditCommand = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
                                   WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                   10, 740, 1100, 30,
                                   hwnd, (HMENU)IDC_EDIT_COMMAND,
                                   GetModuleHandle(NULL), NULL);
    
    SendMessage(g_hEditCommand, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);
    
    // 전송 버튼
    HWND hBtnSend = CreateWindow("BUTTON", "EXECUTE »",
                                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                1120, 740, 120, 30,
                                hwnd, (HMENU)IDC_BTN_SEND_COMMAND,
                                GetModuleHandle(NULL), NULL);
    
    SendMessage(hBtnSend, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
}

// ============================================================================
// Exploit 패널 생성
// ============================================================================
void CreateExploitPanel(HWND hwnd) {
    // 레이블
    HWND hLabel = CreateWindow("STATIC", "Quick Exploit:",
                              WS_CHILD | WS_VISIBLE,
                              10, 785, 120, 20,
                              hwnd, NULL,
                              GetModuleHandle(NULL), NULL);
    
    SendMessage(hLabel, WM_SETFONT, (WPARAM)g_hFontMain, TRUE);
    
    // Exploit 콤보박스
    g_hExploitCombo = CreateWindow("COMBOBOX", "",
                                  WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                                  130, 782, 300, 200,
                                  hwnd, (HMENU)IDC_COMBO_EXPLOIT,
                                  GetModuleHandle(NULL), NULL);
    
    SendMessage(g_hExploitCombo, WM_SETFONT, (WPARAM)g_hFontMain, TRUE);
    
    // Exploit 목록 추가
    SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)"MS08-067 (SMB RCE)");
    SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)"MS17-010 (EternalBlue)");
    SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)"MS03-026 (DCOM RPC)");
    SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)"MS10-015 (Privilege Escalation)");
    SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)"MS11-046 (AFD.sys)");
    SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)"MS06-040 (Server Service)");
    SendMessage(g_hExploitCombo, CB_SETCURSEL, 0, 0);
    
    // Launch 버튼
    HWND hBtnLaunch = CreateWindow("BUTTON", "⚡ LAUNCH EXPLOIT",
                                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  440, 780, 180, 30,
                                  hwnd, (HMENU)IDC_BTN_LAUNCH_EXPLOIT,
                                  GetModuleHandle(NULL), NULL);
    
    SendMessage(hBtnLaunch, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
}

// ============================================================================
// 상태바 생성
// ============================================================================
void CreateStatusBar(HWND hwnd) {
    g_hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
                                 WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                 0, 0, 0, 0,
                                 hwnd, (HMENU)IDC_STATUSBAR,
                                 GetModuleHandle(NULL), NULL);
    
    int statusParts[3] = {200, 400, -1};
    SendMessage(g_hStatusBar, SB_SETPARTS, 3, (LPARAM)statusParts);
    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)"Server: Stopped");
    SendMessage(g_hStatusBar, SB_SETTEXT, 1, (LPARAM)"Sessions: 0");
    SendMessage(g_hStatusBar, SB_SETTEXT, 2, (LPARAM)"Ready");
}

// ============================================================================
// 로그 메시지 추가 (색상 지원)
// ============================================================================
void AddLogMessage(const char* message, COLORREF color) {
    if (!g_hEditLog) return;
    
    // 현재 시간
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "[%H:%M:%S]", t);
    
    // 로그 메시지 포맷
    char logMessage[1024];
    snprintf(logMessage, sizeof(logMessage), "%s %s\r\n", timestamp, message);
    
    // 현재 텍스트 길이
    int length = GetWindowTextLength(g_hEditLog);
    
    // 끝으로 이동
    SendMessage(g_hEditLog, EM_SETSEL, length, length);
    
    // 텍스트 추가
    SendMessage(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)logMessage);
    
    // 자동 스크롤
    SendMessage(g_hEditLog, EM_SCROLLCARET, 0, 0);
}

// ============================================================================
// 세션 리스트 업데이트
// ============================================================================
void UpdateSessionList() {
    ListView_DeleteAllItems(g_hListViewSessions);
    
    // 백엔드에서 세션 정보 가져오기
    // TODO: 실제 구현에서는 server_backend.h의 함수 사용
    
    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(LVITEM));
    
    // 예제 데이터 (실제로는 백엔드에서 가져옴)
    lvi.mask = LVIF_TEXT;
    lvi.iItem = 0;
    
    lvi.iSubItem = 0;
    lvi.pszText = "0";
    ListView_InsertItem(g_hListViewSessions, &lvi);
    
    ListView_SetItemText(g_hListViewSessions, 0, 1, "192.168.1.100");
    ListView_SetItemText(g_hListViewSessions, 0, 2, "TARGET-PC");
    ListView_SetItemText(g_hListViewSessions, 0, 3, "Administrator");
    ListView_SetItemText(g_hListViewSessions, 0, 4, "Windows 7 6.1 Build 7601");
    ListView_SetItemText(g_hListViewSessions, 0, 5, "1234");
    ListView_SetItemText(g_hListViewSessions, 0, 6, "Active");
    ListView_SetItemText(g_hListViewSessions, 0, 7, "Just now");
    
    AddLogMessage("[*] Session list updated", COLOR_TEXT);
}

// ============================================================================
// C2 서버 시작
// ============================================================================
void StartC2Server() {
    if (g_ServerRunning) {
        AddLogMessage("[!] Server is already running", COLOR_ACCENT_RED);
        return;
    }
    
    AddLogMessage("[*] Starting C2 server...", COLOR_ACCENT);
    
    g_ServerRunning = TRUE;
    g_hServerThread = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
    
    if (g_hServerThread) {
        AddLogMessage("[+] Server started successfully on port 4444", COLOR_ACCENT);
        SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)"Server: Running");
        
        // 툴바 버튼 상태 변경
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_START_SERVER), FALSE);
        EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_STOP_SERVER), TRUE);
    } else {
        AddLogMessage("[!] Failed to start server", COLOR_ACCENT_RED);
        g_ServerRunning = FALSE;
    }
}

// ============================================================================
// C2 서버 중지
// ============================================================================
void StopC2Server() {
    if (!g_ServerRunning) {
        AddLogMessage("[!] Server is not running", COLOR_ACCENT_RED);
        return;
    }
    
    AddLogMessage("[*] Stopping C2 server...", COLOR_ACCENT);
    
    g_ServerRunning = FALSE;
    
    if (g_hServerThread) {
        WaitForSingleObject(g_hServerThread, 5000);
        CloseHandle(g_hServerThread);
        g_hServerThread = NULL;
    }
    
    AddLogMessage("[+] Server stopped", COLOR_ACCENT);
    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)"Server: Stopped");
    
    // 툴바 버튼 상태 변경
    EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_START_SERVER), TRUE);
    EnableWindow(GetDlgItem(g_hMainWindow, IDC_BTN_STOP_SERVER), FALSE);
}

// ============================================================================
// 클라이언트에 명령 전송
// ============================================================================
void SendCommandToClient(int sessionId, const char* command) {
    char logMsg[1024];
    snprintf(logMsg, sizeof(logMsg), "[>] Session %d: %s", sessionId, command);
    AddLogMessage(logMsg, COLOR_ACCENT);
    
    // TODO: 실제 명령 전송 구현
    // send_command_to_session(sessionId, command);
}

// ============================================================================
// Exploit 실행
// ============================================================================
void LaunchExploit() {
    int selectedIndex = ListView_GetNextItem(g_hListViewSessions, -1, LVNI_SELECTED);
    
    if (selectedIndex < 0) {
        AddLogMessage("[!] No target selected", COLOR_ACCENT_RED);
        MessageBox(g_hMainWindow, 
                  "Please select a target session first!",
                  "No Target", MB_ICONWARNING);
        return;
    }
    
    int exploitIndex = (int)SendMessage(g_hExploitCombo, CB_GETCURSEL, 0, 0);
    char exploitName[128];
    SendMessage(g_hExploitCombo, CB_GETLBTEXT, exploitIndex, (LPARAM)exploitName);
    
    // 타겟 정보 가져오기
    char targetIP[64];
    ListView_GetItemText(g_hListViewSessions, selectedIndex, 1, targetIP, sizeof(targetIP));
    
    // 확인 다이얼로그
    char confirmMsg[256];
    snprintf(confirmMsg, sizeof(confirmMsg),
            "Launch %s against %s?\n\n"
            "⚠ This will attempt exploitation!\n"
            "⚠ Only use on authorized targets!",
            exploitName, targetIP);
    
    int result = MessageBox(g_hMainWindow, confirmMsg, "Confirm Exploit",
                           MB_ICONWARNING | MB_YESNO);
    
    if (result == IDYES) {
        char logMsg[256];
        snprintf(logMsg, sizeof(logMsg), 
                "[⚡] Launching %s against %s...", exploitName, targetIP);
        AddLogMessage(logMsg, COLOR_ACCENT_RED);
        
        // TODO: 실제 exploit 실행
        // launch_exploit(exploitIndex, targetIP);
        
        AddLogMessage("[*] Exploit launched. Monitor for new sessions...", COLOR_TEXT);
    }
}

// ============================================================================
// 스크린샷 요청
// ============================================================================
void RequestScreenshot(int sessionId) {
    char logMsg[128];
    snprintf(logMsg, sizeof(logMsg), "[*] Requesting screenshot from session %d", sessionId);
    AddLogMessage(logMsg, COLOR_ACCENT);
    
    // TODO: 스크린샷 명령 전송
    // send_command_to_session(sessionId, "screenshot");
}

// ============================================================================
// 서버 스레드
// ============================================================================
DWORD WINAPI ServerThread(LPVOID param) {
    WSADATA wsa;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in server, client;
    int clientSize;
    
    // Winsock 초기화
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        AddLogMessage("[!] WSAStartup failed", COLOR_ACCENT_RED);
        return 1;
    }
    
    // 소켓 생성
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        AddLogMessage("[!] Socket creation failed", COLOR_ACCENT_RED);
        WSACleanup();
        return 1;
    }
    
    // 서버 주소 설정
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(4444);
    
    // 바인드
    if (bind(serverSocket, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        AddLogMessage("[!] Bind failed", COLOR_ACCENT_RED);
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    
    // 리슨
    if (listen(serverSocket, 10) == SOCKET_ERROR) {
        AddLogMessage("[!] Listen failed", COLOR_ACCENT_RED);
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    
    AddLogMessage("[+] Server listening on port 4444", COLOR_ACCENT);
    
    // 연결 수락 루프
    clientSize = sizeof(struct sockaddr_in);
    
    while (g_ServerRunning) {
        // 타임아웃 설정
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(0, &readfds, NULL, NULL, &tv);
        
        if (activity > 0 && FD_ISSET(serverSocket, &readfds)) {
            clientSocket = accept(serverSocket, (struct sockaddr*)&client, &clientSize);
            
            if (clientSocket != INVALID_SOCKET) {
                char clientIP[64];
                strcpy(clientIP, inet_ntoa(client.sin_addr));
                
                char logMsg[128];
                snprintf(logMsg, sizeof(logMsg), "[+] New connection from %s", clientIP);
                AddLogMessage(logMsg, COLOR_ACCENT);
                
                // TODO: 세션 관리 및 핸들러 스레드 생성
                // handle_new_client(clientSocket, &client);
                
                // 세션 카운트 업데이트
                char statusMsg[64];
                snprintf(statusMsg, sizeof(statusMsg), "Sessions: 1"); // TODO: 실제 카운트
                SendMessage(g_hStatusBar, SB_SETTEXT, 1, (LPARAM)statusMsg);
                
                // 리스트 업데이트
                UpdateSessionList();
            }
        }
    }
    
    // 정리
    closesocket(serverSocket);
    WSACleanup();
    
    return 0;
}
