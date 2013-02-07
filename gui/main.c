/*
 * Moonlight C2 Framework - Main GUI (Win32 API)
 * Native Windows application written in C
 */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")

// Window dimensions
#define WINDOW_WIDTH  1200
#define WINDOW_HEIGHT 700

// Control IDs
#define ID_SESSIONS_LIST    1001
#define ID_LISTENERS_LIST   1002
#define ID_EXPLOITS_LIST    1003
#define ID_OUTPUT_TEXT      1004
#define ID_COMMAND_EDIT     1005
#define ID_SEND_BUTTON      1006
#define ID_TAB_CONTROL      1007
#define ID_STATUS_BAR       1008

// Menu IDs
#define IDM_FILE_EXIT       2001
#define IDM_LISTENER_NEW    2002
#define IDM_LISTENER_STOP   2003
#define IDM_SESSION_INTERACT 2004
#define IDM_SESSION_KILL    2005
#define IDM_EXPLOIT_LAUNCH  2006
#define IDM_HELP_ABOUT      2007

// Tab indices
#define TAB_SESSIONS    0
#define TAB_LISTENERS   1
#define TAB_EXPLOITS    2

// Global variables
HWND g_hMainWindow = NULL;
HWND g_hTabControl = NULL;
HWND g_hSessionsList = NULL;
HWND g_hListenersList = NULL;
HWND g_hExploitsList = NULL;
HWND g_hOutputText = NULL;
HWND g_hCommandEdit = NULL;
HWND g_hSendButton = NULL;
HWND g_hStatusBar = NULL;
int g_currentTab = TAB_SESSIONS;

// Forward declarations
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateControls(HWND hwnd);
void CreateMenuBar(HWND hwnd);
void InitializeSessionsList(HWND hList);
void InitializeListenersList(HWND hList);
void InitializeExploitsList(HWND hList);
void OnTabChange(HWND hwnd);
void OnSendCommand(HWND hwnd);
void ShowAboutDialog(HWND hwnd);
void UpdateStatusBar(const char* text);
void AddSession(int id, const char* hostname, const char* ip, const char* os);
void AddListener(const char* protocol, int port, const char* status);
void AddExploit(const char* name, const char* cve, const char* target);
void AppendOutput(const char* text);

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wc = {0};
    MSG msg;
    
    // Initialize common controls
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);
    
    // Register window class
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = 0;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = "MoonlightC2Class";
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    
    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, "Window Registration Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }
    
    // Create main window
    g_hMainWindow = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "MoonlightC2Class",
        "Moonlight C2 Framework v2.0",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, hInstance, NULL
    );
    
    if (g_hMainWindow == NULL) {
        MessageBox(NULL, "Window Creation Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }
    
    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);
    
    // Message loop
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return msg.wParam;
}

// Window procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            CreateMenuBar(hwnd);
            CreateControls(hwnd);
            UpdateStatusBar("Ready");
            
            // Add sample data
            AddSession(1, "DESKTOP-ABC123", "192.168.1.100", "Windows 10");
            AddSession(2, "SERVER-XYZ", "192.168.1.50", "Windows Server 2016");
            AddListener("TCP", 4444, "Active");
            AddListener("HTTP", 8080, "Stopped");
            AddExploit("EternalBlue", "MS17-010", "Windows 7/2008");
            AddExploit("NetAPI RPC", "MS08-067", "Windows XP/2003");
            AddExploit("RPC DCOM", "MS03-026", "Windows 2000/XP");
            
            break;
            
        case WM_SIZE:
            // Resize controls
            if (g_hTabControl) {
                RECT rcClient;
                GetClientRect(hwnd, &rcClient);
                
                int statusHeight = 20;
                SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
                
                SetWindowPos(g_hTabControl, NULL, 0, 0, 
                    rcClient.right, rcClient.bottom - statusHeight - 150, 
                    SWP_NOZORDER);
                
                SetWindowPos(g_hOutputText, NULL, 0, rcClient.bottom - statusHeight - 150,
                    rcClient.right - 100, 100, SWP_NOZORDER);
                
                SetWindowPos(g_hCommandEdit, NULL, 0, rcClient.bottom - statusHeight - 50,
                    rcClient.right - 100, 25, SWP_NOZORDER);
                
                SetWindowPos(g_hSendButton, NULL, rcClient.right - 95, rcClient.bottom - statusHeight - 50,
                    90, 25, SWP_NOZORDER);
            }
            break;
            
        case WM_NOTIFY: {
            LPNMHDR pnmh = (LPNMHDR)lParam;
            if (pnmh->idFrom == ID_TAB_CONTROL && pnmh->code == TCN_SELCHANGE) {
                OnTabChange(hwnd);
            }
            else if (pnmh->code == NM_DBLCLK) {
                if (pnmh->idFrom == ID_SESSIONS_LIST) {
                    AppendOutput("[*] Session interaction not yet implemented\n");
                }
                else if (pnmh->idFrom == ID_EXPLOITS_LIST) {
                    AppendOutput("[*] Exploit launch not yet implemented\n");
                }
            }
            break;
        }
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDM_FILE_EXIT:
                    PostQuitMessage(0);
                    break;
                    
                case IDM_LISTENER_NEW:
                    MessageBox(hwnd, "New listener dialog", "Info", MB_OK);
                    break;
                    
                case IDM_SESSION_INTERACT:
                    AppendOutput("[*] Opening session interaction...\n");
                    break;
                    
                case IDM_SESSION_KILL:
                    AppendOutput("[*] Killing session...\n");
                    break;
                    
                case IDM_EXPLOIT_LAUNCH:
                    AppendOutput("[*] Launching exploit...\n");
                    break;
                    
                case IDM_HELP_ABOUT:
                    ShowAboutDialog(hwnd);
                    break;
                    
                case ID_SEND_BUTTON:
                    OnSendCommand(hwnd);
                    break;
            }
            break;
            
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Create menu bar
void CreateMenuBar(HWND hwnd) {
    HMENU hMenuBar = CreateMenu();
    HMENU hFile = CreateMenu();
    HMENU hListener = CreateMenu();
    HMENU hSession = CreateMenu();
    HMENU hExploit = CreateMenu();
    HMENU hHelp = CreateMenu();
    
    // File menu
    AppendMenu(hFile, MF_STRING, IDM_FILE_EXIT, "E&xit");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hFile, "&File");
    
    // Listener menu
    AppendMenu(hListener, MF_STRING, IDM_LISTENER_NEW, "&New Listener");
    AppendMenu(hListener, MF_STRING, IDM_LISTENER_STOP, "&Stop Listener");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hListener, "&Listeners");
    
    // Session menu
    AppendMenu(hSession, MF_STRING, IDM_SESSION_INTERACT, "&Interact");
    AppendMenu(hSession, MF_STRING, IDM_SESSION_KILL, "&Kill Session");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hSession, "&Sessions");
    
    // Exploit menu
    AppendMenu(hExploit, MF_STRING, IDM_EXPLOIT_LAUNCH, "&Launch Exploit");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hExploit, "&Exploits");
    
    // Help menu
    AppendMenu(hHelp, MF_STRING, IDM_HELP_ABOUT, "&About");
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hHelp, "&Help");
    
    SetMenu(hwnd, hMenuBar);
}

// Create all controls
void CreateControls(HWND hwnd) {
    RECT rcClient;
    GetClientRect(hwnd, &rcClient);
    
    // Create tab control
    g_hTabControl = CreateWindowEx(
        0, WC_TABCONTROL, "",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, rcClient.right, rcClient.bottom - 150,
        hwnd, (HMENU)ID_TAB_CONTROL, GetModuleHandle(NULL), NULL
    );
    
    // Add tabs
    TCITEM tie;
    tie.mask = TCIF_TEXT;
    
    tie.pszText = "Sessions";
    TabCtrl_InsertItem(g_hTabControl, TAB_SESSIONS, &tie);
    
    tie.pszText = "Listeners";
    TabCtrl_InsertItem(g_hTabControl, TAB_LISTENERS, &tie);
    
    tie.pszText = "Exploits";
    TabCtrl_InsertItem(g_hTabControl, TAB_EXPLOITS, &tie);
    
    // Get tab display area
    RECT rcTab;
    GetClientRect(g_hTabControl, &rcTab);
    TabCtrl_AdjustRect(g_hTabControl, FALSE, &rcTab);
    
    // Create sessions list view
    g_hSessionsList = CreateWindowEx(
        WS_EX_CLIENTEDGE, WC_LISTVIEW, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        rcTab.left, rcTab.top, rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        g_hTabControl, (HMENU)ID_SESSIONS_LIST, GetModuleHandle(NULL), NULL
    );
    InitializeSessionsList(g_hSessionsList);
    
    // Create listeners list view
    g_hListenersList = CreateWindowEx(
        WS_EX_CLIENTEDGE, WC_LISTVIEW, "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
        rcTab.left, rcTab.top, rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        g_hTabControl, (HMENU)ID_LISTENERS_LIST, GetModuleHandle(NULL), NULL
    );
    InitializeListenersList(g_hListenersList);
    
    // Create exploits list view
    g_hExploitsList = CreateWindowEx(
        WS_EX_CLIENTEDGE, WC_LISTVIEW, "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
        rcTab.left, rcTab.top, rcTab.right - rcTab.left, rcTab.bottom - rcTab.top,
        g_hTabControl, (HMENU)ID_EXPLOITS_LIST, GetModuleHandle(NULL), NULL
    );
    InitializeExploitsList(g_hExploitsList);
    
    // Create output text box
    g_hOutputText = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | 
        ES_READONLY | WS_VSCROLL,
        0, rcClient.bottom - 150, rcClient.right - 100, 100,
        hwnd, (HMENU)ID_OUTPUT_TEXT, GetModuleHandle(NULL), NULL
    );
    
    // Create command input
    g_hCommandEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, rcClient.bottom - 50, rcClient.right - 100, 25,
        hwnd, (HMENU)ID_COMMAND_EDIT, GetModuleHandle(NULL), NULL
    );
    
    // Create send button
    g_hSendButton = CreateWindow(
        "BUTTON", "Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rcClient.right - 95, rcClient.bottom - 50, 90, 25,
        hwnd, (HMENU)ID_SEND_BUTTON, GetModuleHandle(NULL), NULL
    );
    
    // Create status bar
    g_hStatusBar = CreateWindowEx(
        0, STATUSCLASSNAME, "",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hwnd, (HMENU)ID_STATUS_BAR, GetModuleHandle(NULL), NULL
    );
    
    // Set font for all controls
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(g_hOutputText, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(g_hCommandEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(g_hSendButton, WM_SETFONT, (WPARAM)hFont, TRUE);
}

// Initialize sessions list view
void InitializeSessionsList(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = "ID";
    lvc.cx = 50;
    ListView_InsertColumn(hList, 0, &lvc);
    
    lvc.pszText = "Hostname";
    lvc.cx = 200;
    ListView_InsertColumn(hList, 1, &lvc);
    
    lvc.pszText = "IP Address";
    lvc.cx = 150;
    ListView_InsertColumn(hList, 2, &lvc);
    
    lvc.pszText = "OS";
    lvc.cx = 150;
    ListView_InsertColumn(hList, 3, &lvc);
    
    lvc.pszText = "Status";
    lvc.cx = 100;
    ListView_InsertColumn(hList, 4, &lvc);
}

// Initialize listeners list view
void InitializeListenersList(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = "Protocol";
    lvc.cx = 100;
    ListView_InsertColumn(hList, 0, &lvc);
    
    lvc.pszText = "Port";
    lvc.cx = 80;
    ListView_InsertColumn(hList, 1, &lvc);
    
    lvc.pszText = "Status";
    lvc.cx = 100;
    ListView_InsertColumn(hList, 2, &lvc);
    
    lvc.pszText = "Connections";
    lvc.cx = 100;
    ListView_InsertColumn(hList, 3, &lvc);
}

// Initialize exploits list view
void InitializeExploitsList(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = "Name";
    lvc.cx = 200;
    ListView_InsertColumn(hList, 0, &lvc);
    
    lvc.pszText = "CVE";
    lvc.cx = 120;
    ListView_InsertColumn(hList, 1, &lvc);
    
    lvc.pszText = "Target";
    lvc.cx = 200;
    ListView_InsertColumn(hList, 2, &lvc);
    
    lvc.pszText = "Type";
    lvc.cx = 100;
    ListView_InsertColumn(hList, 3, &lvc);
}

// Handle tab change
void OnTabChange(HWND hwnd) {
    int iPage = TabCtrl_GetCurSel(g_hTabControl);
    
    ShowWindow(g_hSessionsList, SW_HIDE);
    ShowWindow(g_hListenersList, SW_HIDE);
    ShowWindow(g_hExploitsList, SW_HIDE);
    
    switch (iPage) {
        case TAB_SESSIONS:
            ShowWindow(g_hSessionsList, SW_SHOW);
            UpdateStatusBar("Sessions");
            break;
        case TAB_LISTENERS:
            ShowWindow(g_hListenersList, SW_SHOW);
            UpdateStatusBar("Listeners");
            break;
        case TAB_EXPLOITS:
            ShowWindow(g_hExploitsList, SW_SHOW);
            UpdateStatusBar("Exploits");
            break;
    }
    
    g_currentTab = iPage;
}

// Handle send command
void OnSendCommand(HWND hwnd) {
    char command[1024];
    GetWindowText(g_hCommandEdit, command, sizeof(command));
    
    if (strlen(command) > 0) {
        char output[2048];
        sprintf(output, "> %s\n", command);
        AppendOutput(output);
        
        // TODO: Send command to selected session
        AppendOutput("[*] Command sent to active session\n");
        
        SetWindowText(g_hCommandEdit, "");
    }
}

// Show about dialog
void ShowAboutDialog(HWND hwnd) {
    MessageBox(hwnd,
        "Moonlight C2 Framework v2.0\n\n"
        "Advanced Command & Control Framework\n"
        "Written in C with Win32 API\n\n"
        "Features:\n"
        "- Assembly-enhanced implants\n"
        "- 38+ CVE exploits\n"
        "- Complete monitoring & control\n"
        "- Direct syscalls & EDR bypass\n\n"
        "For authorized penetration testing only!",
        "About Moonlight C2",
        MB_OK | MB_ICONINFORMATION
    );
}

// Update status bar
void UpdateStatusBar(const char* text) {
    if (g_hStatusBar) {
        SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)text);
    }
}

// Add session to list
void AddSession(int id, const char* hostname, const char* ip, const char* os) {
    char idStr[16];
    sprintf(idStr, "%d", id);
    
    LVITEM lvi = {0};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(g_hSessionsList);
    lvi.iSubItem = 0;
    lvi.pszText = idStr;
    
    int index = ListView_InsertItem(g_hSessionsList, &lvi);
    
    ListView_SetItemText(g_hSessionsList, index, 1, (char*)hostname);
    ListView_SetItemText(g_hSessionsList, index, 2, (char*)ip);
    ListView_SetItemText(g_hSessionsList, index, 3, (char*)os);
    ListView_SetItemText(g_hSessionsList, index, 4, "Active");
}

// Add listener to list
void AddListener(const char* protocol, int port, const char* status) {
    char portStr[16];
    sprintf(portStr, "%d", port);
    
    LVITEM lvi = {0};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(g_hListenersList);
    lvi.iSubItem = 0;
    lvi.pszText = (char*)protocol;
    
    int index = ListView_InsertItem(g_hListenersList, &lvi);
    
    ListView_SetItemText(g_hListenersList, index, 1, portStr);
    ListView_SetItemText(g_hListenersList, index, 2, (char*)status);
    ListView_SetItemText(g_hListenersList, index, 3, "0");
}

// Add exploit to list
void AddExploit(const char* name, const char* cve, const char* target) {
    LVITEM lvi = {0};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(g_hExploitsList);
    lvi.iSubItem = 0;
    lvi.pszText = (char*)name;
    
    int index = ListView_InsertItem(g_hExploitsList, &lvi);
    
    ListView_SetItemText(g_hExploitsList, index, 1, (char*)cve);
    ListView_SetItemText(g_hExploitsList, index, 2, (char*)target);
    ListView_SetItemText(g_hExploitsList, index, 3, "Remote");
}

// Append text to output
void AppendOutput(const char* text) {
    int len = GetWindowTextLength(g_hOutputText);
    SendMessage(g_hOutputText, EM_SETSEL, len, len);
    SendMessage(g_hOutputText, EM_REPLACESEL, FALSE, (LPARAM)text);
}
