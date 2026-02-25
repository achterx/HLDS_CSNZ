#include <windows.h>
#include "HLSDK/common/interface.h"
#include "ICommandLine.h"
#include "IFileSystem.h"
#include "sys.h"
#include "hook.h"
#include <stdio.h>
#include <thread>
#include <chrono>

//DLL State Flags

#define DLL_INACTIVE 0		// no dll
#define DLL_ACTIVE   1		// dll is running
#define DLL_PAUSED   2		// dll is paused
#define DLL_CLOSE    3		// closing down dll
#define DLL_TRANS    4 		// Level Transition

// DLL Pause reasons

#define DLL_NORMAL        0   // User hit Esc or something.
#define DLL_QUIT          4   // Quit now
#define DLL_RESTART       5   // Switch to launcher for linux, does a quit but returns 1

// DLL Substate info ( not relevant )
#define ENG_NORMAL         (1<<0)

#define LAUNCHER_ERROR	-1
#define LAUNCHER_OK		0

char g_pLogFile[MAX_PATH];
char g_pConsoleTitle[MAX_PATH];
int g_iPort = 27015;

// Heavy debug logging helper - defined early so all code below can use it
static void HLDS_Log(const char* fmt, ...)
{
    char buf[2048];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    printf("[HLDS_DBG] %s\n", buf);
    fflush(stdout);
    FILE* f = fopen("hlds_debug.log", "a");
    if (f) { fprintf(f, "[HLDS_DBG] %s\n", buf); fclose(f); }
}

class IDedicatedExports : public IBaseInterface
{
public:
    virtual ~IDedicatedExports() {};
    virtual void Sys_Printf(const char* text) = 0;
};

#define VENGINE_DEDICATEDEXPORTS_API_VERSION "VENGINE_DEDICATEDEXPORTS_API_VERSION001"

class CDedicatedExports : public IDedicatedExports {
public:
    void Sys_Printf(const char* text);
};

EXPOSE_SINGLE_INTERFACE(CDedicatedExports, IDedicatedExports, VENGINE_DEDICATEDEXPORTS_API_VERSION);

void CDedicatedExports::Sys_Printf(const char* text)
{
    printf(text);
}

class IDedicatedServerAPI : public IBaseInterface
{
public:
    virtual ~IDedicatedServerAPI() {};
    virtual bool Init(const char* basedir, const char* cmdline, CreateInterfaceFn launcherFactory, CreateInterfaceFn filesystemFactory) = 0;
    virtual int Shutdown() = 0;
    virtual bool RunFrame() = 0;
    virtual char* AddConsoleText(char* text) = 0;
    virtual void* UpdateStatus(float* fps, int* nActive, int* nMaxPlayers, char* pszMap) = 0;
};

class CDedicatedServerAPI : public IDedicatedServerAPI
{
private:
    char m_OrigCmd[1024];

public:
    bool Init(const char* basedir, const char* cmdline, CreateInterfaceFn launcherFactory, CreateInterfaceFn filesystemFactory)
    {
        HLDS_Log("=== Init() START ===");
        HLDS_Log("basedir = '%s'", basedir);
        HLDS_Log("cmdline = '%s'", cmdline);

        HLDS_Log("Getting IDedicatedExports... g_pDediInitDwordExport=%p", g_pDediInitDwordExport);
        *(IDedicatedExports**)g_pDediInitDwordExport = (IDedicatedExports*)launcherFactory(VENGINE_DEDICATEDEXPORTS_API_VERSION, nullptr);
        if (!*(IDedicatedExports**)g_pDediInitDwordExport)
        {
            HLDS_Log("FATAL: IDedicatedExports is NULL!");
            return false;
        }
        HLDS_Log("IDedicatedExports OK: %p", *(IDedicatedExports**)g_pDediInitDwordExport);

        strncpy(this->m_OrigCmd, cmdline, ARRAYSIZE(this->m_OrigCmd));
        this->m_OrigCmd[ARRAYSIZE(this->m_OrigCmd) - 1] = 0;

        HLDS_Log("Calling DediInitFunc1 (Sys_InitArgv)...");
        g_pfnDediInitFunc1("Sys_InitArgv( m_OrigCmd )", "Sys_ShutdownArgv()", 0);
        HLDS_Log("Calling DediInitFunc2 (ParseCmdLine)...");
        g_pfnDediInitFunc2(this->m_OrigCmd);
        HLDS_Log("SetQuitting(0) + g_pIsDedicated=true...");
        g_pCEngine->SetQuitting(0);
        g_pIsDedicated = true;

        HLDS_Log("Calling DediInitFunc1 (FileSystem_Init)...");
        g_pfnDediInitFunc1("FileSystem_Init(basedir, (void *)filesystemFactory)", "FileSystem_Shutdown()", 0);
        HLDS_Log("Calling DediInitFunc3 (FileSystem init basedir)...");
        if (!g_pfnDediInitFunc3(basedir, (void*)filesystemFactory))
        {
            HLDS_Log("FATAL: DediInitFunc3 (FileSystem init) returned false!");
            return false;
        }
        HLDS_Log("FileSystem init OK");

        HLDS_Log("CGame::CreateWin()...");
        g_pCGame->CreateWin();
        HLDS_Log("CGame::Init(nullptr)...");
        if (!g_pCGame->Init(nullptr))
        {
            HLDS_Log("FATAL: CGame::Init failed!");
            return false;
        }
        HLDS_Log("CGame::Init OK");

        char buffer[MAX_PATH];
        __time64_t currentTime = 0;
        currentTime = _time64(NULL);

        struct tm localTime;
        _localtime64_s(&localTime, &currentTime);

        DWORD pid = GetCurrentProcessId();
        HLDS_Log("PID=%u, Port=%d, LogFile='%s'", pid, g_iPort, g_pLogFile);

        g_pfnDediInitFunc5(buffer, "%s_%04d%02d%02d_%02d%02d%02d_%u_%d.log", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);
        HLDS_Log("Log buffer = '%s'", buffer);
        g_pfnDediInitFunc5(g_pDediInitDword5, "%sFatal_%04d%02d%02d_%02d%02d%02d_%u_%d.log", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);
        g_pfnDediInitFunc5(g_pDediInitDword6, "%s_##ADDR##_%04d%02d%02d_%02d%02d%02d_%u.dmp", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);

        snprintf(g_pConsoleTitle, sizeof(g_pConsoleTitle), "%s_%04d%02d%02d_%02d%02d%02d_%u_%d", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);
        HLDS_Log("Console title = '%s'", g_pConsoleTitle);

        HLDS_Log("Calling DediInitFunc8 (init log)...");
        g_pfnDediInitFunc8(buffer, 0, 0);
        HLDS_Log("DediInitFunc8 OK");

        void* hwnd = g_pCGame->Func24();
        HLDS_Log("HWND from CGame::Func24() = %p", hwnd);
        g_pfnDediInitFunc6(hwnd);
        HLDS_Log("DediInitFunc6 OK");

        HLDS_Log("Setting BaseSocket HWND... g_pBaseSocket=%p", (void*)g_pBaseSocket);
        HLDS_Log("  *(DWORD*)g_pBaseSocket = 0x%08X", *(DWORD*)g_pBaseSocket);
        HLDS_Log("  offset+0xC addr = %p", (void*)(*(DWORD*)g_pBaseSocket + 0xC));
        *(DWORD**)(*(DWORD*)g_pBaseSocket + 0xC) = (DWORD*)g_pCGame->Func24();
        HLDS_Log("BaseSocket HWND set OK");

        HLDS_Log("CGame::Shutdown()...");
        g_pCGame->Shutdown();
        HLDS_Log("CGame::Shutdown OK");

        HLDS_Log("DediInitFunc10(buffer)...");
        g_pfnDediInitFunc10(buffer);
        HLDS_Log("DediInitFunc10(Dword5)...");
        g_pfnDediInitFunc10(g_pDediInitDword5);
        HLDS_Log("DediInitFunc10 OK");

        HLDS_Log("CEngine::Load(basedir='%s', cmdline='%s')...", basedir, cmdline);
        if (!g_pCEngine->Load(basedir, cmdline, nullptr, buffer))
        {
            HLDS_Log("FATAL: CEngine::Load failed!");
            return false;
        }
        HLDS_Log("CEngine::Load OK");

        HLDS_Log("Executing server.cfg via DediInitFunc7...");
        g_pfnDediInitFunc7("exec server.cfg\n");
        HLDS_Log("DediInitFunc7 OK");

        HLDS_Log("g_pPacketHostServer = %p", (void*)g_pPacketHostServer);
        if (g_pPacketHostServer)
        {
            HLDS_Log("Calling DediInitFunc9 (register HostServer packet handler)...");
            g_pfnDediInitFunc9(g_pPacketHostServer, buffer);
            HLDS_Log("DediInitFunc9 OK");
        }
        else
        {
            HLDS_Log("WARNING: g_pPacketHostServer is NULL! HostServer packet handler NOT registered!");
        }

        HLDS_Log("=== Init() COMPLETE - returning true ===");
        return true;
    };
    int Shutdown()
    {
        g_pCEngine->Unload();
        g_pCGame->DestroyWin();
        g_pfnDediShutdownFunc1("FileSystem_Shutdown()", 0);
        g_pfnDediShutdownFunc2();
        g_pfnDediShutdownFunc1("Sys_ShutdownArgv()", 0);
        *(void**)g_pDediInitDwordExport = nullptr;
        return *(int*)g_pServerState;
    };
    bool RunFrame()
    {
        if (g_pCEngine->GetQuitting())
        {
            return false;
        }
        g_pCEngine->Frame();
        return true;
    };
    char* AddConsoleText(char* text)
    {
        return g_pfnDediAddTextFunc(text);
    };
    void* UpdateStatus(float* fps, int* nActive, int* nMaxPlayers, char* pszMap)
    {
        return g_pfnDediUpdateStatusFunc(fps, nActive, nullptr, nMaxPlayers, pszMap);
    };
};
#define VENGINE_HLDS_API_VERSION "VENGINE_HLDS_API_VERSION002"

EXPOSE_SINGLE_INTERFACE(CDedicatedServerAPI, IDedicatedServerAPI, VENGINE_HLDS_API_VERSION);

using SleepFunc = void (*)();
SleepFunc sleep_thread = nullptr;

int g_iPingBoost = 0;
bool g_bTerminated = false;
IFileSystem* g_pFileSystem;
IDedicatedServerAPI* engineAPI = NULL;

HANDLE hConsoleInput;
HANDLE hConsoleOutput;

int m_nConsoleTextLen;
int m_nCursorPosition;
char m_szConsoleText[256];

char m_szSavedConsoleText[256];
int m_nSavedConsoleTextLen;

char m_aszLineBuffer[10][256];
int m_nInputLine;
int m_nBrowseLine;
int m_nTotalLines;

#define DEFAULT_IP "0.0.0.0"
#define DEFAULT_LOBBYPORT "30002"
#define DEFAULT_PORT "27015"
#define DEFAULT_LOGFILE "csods"

HINTERFACEMODULE LoadFilesystemModule(void)
{
    HINTERFACEMODULE hModule = Sys_LoadModule("filesystem_nar.dll");

    if (!hModule)
    {
        MessageBox(NULL, "Could not load filesystem dll.\nFileSystem crashed during construction.", "Fatal Error", MB_ICONERROR);
        return NULL;
    }

    return hModule;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD CtrlType)
{
    switch (CtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_bTerminated = true;
        return TRUE;
    default:
        break;
    }

    return FALSE;
}

void UpdateStatus(int force)
{
    static double tLast = 0.0;
    char szStatus[256];
    int n, nMax;
    char szMap[32];
    float fps;

    if (!engineAPI)
        return;

    double tCurrent = timeGetTime() * 0.001;
    engineAPI->UpdateStatus(&fps, &n, &nMax, szMap);

    if (!force)
    {
        if ((tCurrent - tLast) < 0.5f)
            return;
    }

    tLast = tCurrent;
    snprintf(szStatus, sizeof(szStatus), "%s - %.1f fps %2i/%2i on %16s", g_pConsoleTitle, fps, n, nMax, szMap);

    SetConsoleTitle(szStatus);
}

void Console_Init()
{
    hConsoleInput = GetStdHandle(STD_INPUT_HANDLE);
    hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);

    memset(m_szConsoleText, 0, sizeof(m_szConsoleText));
    m_nConsoleTextLen = 0;
    m_nCursorPosition = 0;

    memset(m_szSavedConsoleText, 0, sizeof(m_szSavedConsoleText));
    m_nSavedConsoleTextLen = 0;

    memset(m_aszLineBuffer, 0, sizeof(m_aszLineBuffer));
    m_nTotalLines = 0;
    m_nInputLine = 0;
    m_nBrowseLine = 0;
}

void Console_PrintRaw(const char* pszMsg, int nChars)
{
    char outputStr[2048];
    WCHAR unicodeStr[1024];

    DWORD nSize = MultiByteToWideChar(CP_UTF8, 0, pszMsg, -1, NULL, 0);
    if (nSize > sizeof(unicodeStr))
        return;

    MultiByteToWideChar(CP_UTF8, 0, pszMsg, -1, unicodeStr, nSize);
    DWORD nLength = WideCharToMultiByte(CP_OEMCP, 0, unicodeStr, -1, 0, 0, NULL, NULL);
    if (nLength > sizeof(outputStr))
        return;

    WideCharToMultiByte(CP_OEMCP, 0, unicodeStr, -1, outputStr, nLength, NULL, NULL);
    WriteFile(hConsoleOutput, outputStr, nChars ? nChars : strlen(outputStr), NULL, NULL);
}

void Console_Echo(const char* pszMsg, int nChars = 0)
{
    Console_PrintRaw(pszMsg, nChars);
}

const char* Console_GetLine()
{
    while (true)
    {
        INPUT_RECORD recs[1024];
        unsigned long numread;
        unsigned long numevents;

        if (!GetNumberOfConsoleInputEvents(hConsoleInput, &numevents))
            return nullptr;
        if (numevents <= 0)
            break;
        if (!ReadConsoleInput(hConsoleInput, recs, ARRAYSIZE(recs), &numread))
            return nullptr;
        if (numread == 0)
            return nullptr;

        for (int i = 0; i < (int)numread; i++)
        {
            INPUT_RECORD* pRec = &recs[i];
            if (pRec->EventType != KEY_EVENT)
                continue;

            if (pRec->Event.KeyEvent.bKeyDown)
            {
                // check for cursor keys
                if (pRec->Event.KeyEvent.wVirtualKeyCode == VK_UP)
                {
                    int nLastCommandInHistory = m_nInputLine + 1;
                    if (nLastCommandInHistory > m_nTotalLines)
                        nLastCommandInHistory = 0;

                    if (m_nBrowseLine == nLastCommandInHistory)
                        break;

                    if (m_nBrowseLine == m_nInputLine)
                    {
                        if (m_nConsoleTextLen > 0)
                            strncpy(m_szSavedConsoleText, m_szConsoleText, m_nConsoleTextLen);
                        m_nSavedConsoleTextLen = m_nConsoleTextLen;
                    }

                    m_nBrowseLine--;
                    if (m_nBrowseLine < 0)
                        m_nBrowseLine = m_nTotalLines - 1;

                    // delete old line
                    while (m_nConsoleTextLen--)
                        Console_Echo("\b \b");

                    // copy buffered line
                    Console_Echo(m_aszLineBuffer[m_nBrowseLine]);

                    strncpy(m_szConsoleText, m_aszLineBuffer[m_nBrowseLine], 256);

                    m_nConsoleTextLen = strlen(m_aszLineBuffer[m_nBrowseLine]);
                    m_nCursorPosition = m_nConsoleTextLen;
                }
                else if (pRec->Event.KeyEvent.wVirtualKeyCode == VK_DOWN)
                {
                    if (m_nBrowseLine == m_nInputLine)
                        break;

                    if (++m_nBrowseLine > m_nTotalLines)
                        m_nBrowseLine = 0;

                    while (m_nConsoleTextLen--)
                        Console_Echo("\b \b");

                    if (m_nBrowseLine == m_nInputLine)
                    {
                        if (m_nSavedConsoleTextLen > 0)
                        {
                            strncpy(m_szConsoleText, m_szSavedConsoleText, m_nSavedConsoleTextLen);
                            Console_Echo(m_szConsoleText, m_nSavedConsoleTextLen);
                        }

                        m_nConsoleTextLen = m_nSavedConsoleTextLen;
                    }
                    else
                    {
                        Console_Echo(m_aszLineBuffer[m_nBrowseLine]);
                        strncpy(m_szConsoleText, m_aszLineBuffer[m_nBrowseLine], 256);
                        m_nConsoleTextLen = strlen(m_aszLineBuffer[m_nBrowseLine]);
                    }

                    m_nCursorPosition = m_nConsoleTextLen;
                }
                else if (pRec->Event.KeyEvent.wVirtualKeyCode == VK_LEFT)
                {
                    if (m_nCursorPosition == 0)
                        break;

                    Console_Echo("\b");
                    m_nCursorPosition--;
                }
                else if (pRec->Event.KeyEvent.wVirtualKeyCode == VK_RIGHT)
                {
                    if (m_nCursorPosition == m_nConsoleTextLen)
                        break;

                    Console_Echo(m_szConsoleText + m_nCursorPosition, 1);
                    m_nCursorPosition++;
                }
                else
                {
                    int nLen;
                    char ch = pRec->Event.KeyEvent.uChar.AsciiChar;
                    switch (ch)
                    {
                    case '\r': // Enter
                    {
                        int nLen = 0;

                        Console_Echo("\n");

                        if (m_nConsoleTextLen)
                        {
                            nLen = m_nConsoleTextLen;

                            m_szConsoleText[m_nConsoleTextLen] = '\0';
                            m_nConsoleTextLen = 0;
                            m_nCursorPosition = 0;

                            // cache line in buffer, but only if it's not a duplicate of the previous line
                            if ((m_nInputLine == 0) || (strcmp(m_aszLineBuffer[m_nInputLine - 1], m_szConsoleText)))
                            {
                                strncpy(m_aszLineBuffer[m_nInputLine], m_szConsoleText, 256);
                                m_nInputLine++;

                                if (m_nInputLine > m_nTotalLines)
                                    m_nTotalLines = m_nInputLine;

                                if (m_nInputLine >= 10)
                                    m_nInputLine = 0;

                            }

                            m_nBrowseLine = m_nInputLine;
                        }

                        if (nLen)
                            return m_szConsoleText;
                        break;
                    }
                    case '\b': // Backspace
                    {
                        int nCount;

                        if (m_nCursorPosition == 0)
                            break;

                        m_nConsoleTextLen--;
                        m_nCursorPosition--;

                        Console_Echo("\b");

                        for (nCount = m_nCursorPosition; nCount < m_nConsoleTextLen; ++nCount)
                        {
                            m_szConsoleText[nCount] = m_szConsoleText[nCount + 1];
                            Console_Echo(m_szConsoleText + nCount, 1);
                        }

                        Console_Echo(" ");

                        nCount = m_nConsoleTextLen;
                        while (nCount >= m_nCursorPosition)
                        {
                            Console_Echo("\b");
                            nCount--;
                        }

                        m_nBrowseLine = m_nInputLine;
                        break;
                    }
                    case '\t': // TAB
                        //ReceiveTab(); // not available in console
                        break;
                    default: // dont' accept nonprintable chars
                        if ((ch >= ' ') && (ch <= '~'))
                        {
                            int nCount;

                            // If the line buffer is maxed out, ignore this char
                            if ((unsigned)m_nConsoleTextLen >= (sizeof(m_szConsoleText) - 2))
                                break;

                            nCount = m_nConsoleTextLen;
                            while (nCount > m_nCursorPosition)
                            {
                                m_szConsoleText[nCount] = m_szConsoleText[nCount - 1];
                                nCount--;
                            }

                            m_szConsoleText[m_nCursorPosition] = ch;

                            Console_Echo(m_szConsoleText + m_nCursorPosition, m_nConsoleTextLen - m_nCursorPosition + 1);

                            m_nConsoleTextLen++;
                            m_nCursorPosition++;

                            nCount = m_nConsoleTextLen;
                            while (nCount > m_nCursorPosition)
                            {
                                Console_Echo("\b");
                                nCount--;
                            }

                            m_nBrowseLine = m_nInputLine;
                        }
                        break;
                    }
                }
            }
        }
    }

    return nullptr;
}

void PrepareConsoleInput()
{
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE)) {
        if (!GetMessage(&msg, nullptr, 0, 0)) {
            break;
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void ProcessConsoleInput()
{
    if (!engineAPI)
        return;

    const char* inputLine = Console_GetLine();
    if (inputLine)
    {
        char szBuf[256];
        snprintf(szBuf, sizeof(szBuf), "%s\n", inputLine);
        engineAPI->AddConsoleText(szBuf);
    }
}

// pingboost 0
void sleep_1ms() noexcept
{
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(1ms);
}

static NTSTATUS(__stdcall* NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER)) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtDelayExecution");
static NTSTATUS(__stdcall* ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG)) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwSetTimerResolution");

// pingboost 4
void sleep_timer() noexcept
{
    ::LARGE_INTEGER interval;
    interval.QuadPart = -1LL;
    NtDelayExecution(FALSE, &interval);
}

// pingboost 5
void yield_thread() noexcept
{
    std::this_thread::yield();
}

int main(int argc, char* argv)
{
    Console_Init();
    SetConsoleTitleA("CSO HLDS");
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // Delete old debug log on fresh start
    DeleteFileA("hlds_debug.log");
    HLDS_Log("=== HLDS main() START ===");
    HLDS_Log("Raw cmdline: %s", GetCommandLine());

    g_bTerminated = false;

    do {
        CommandLine()->CreateCmdLine(GetCommandLine());
        CommandLine()->RemoveParm("-steam");
        CommandLine()->AppendParm("-console", nullptr);

        WSAData WSAData;
        WSAStartup(0x202, &WSAData);
        HLDS_Log("WSAStartup OK");

        if (CommandLine()->CheckParm("-lang") == NULL)
            CommandLine()->AppendParm("-lang", "na_");

        // -ip: default to 0.0.0.0 to listen on ALL interfaces (including Radmin)
        const char* ipParam = NULL;
        if (CommandLine()->CheckParm("-ip", &ipParam) == NULL)
        {
            CommandLine()->AppendParm("-ip", DEFAULT_IP);
            HLDS_Log("-ip not set, defaulting to %s (listen on all interfaces)", DEFAULT_IP);
        }
        else
            HLDS_Log("-ip explicitly set to: %s", ipParam ? ipParam : "(null)");

        if (CommandLine()->CheckParm("-lobbyport") == NULL)
            CommandLine()->AppendParm("-lobbyport", DEFAULT_LOBBYPORT);

        const char* port;
        if (CommandLine()->CheckParm("-port", &port) == NULL)
        {
            CommandLine()->AppendParm("-port", DEFAULT_PORT);
            g_iPort = atoi(DEFAULT_PORT);
            HLDS_Log("-port not set, defaulting to %d", g_iPort);
        }
        else if (port)
        {
            g_iPort = atoi(port);
            HLDS_Log("-port set to %d", g_iPort);
        }

        const char* logfile;
        if (CommandLine()->CheckParm("-logfile", &logfile) == NULL)
        {
            CommandLine()->AppendParm("-logfile", DEFAULT_LOGFILE);
            memcpy(g_pLogFile, DEFAULT_LOGFILE, sizeof(g_pLogFile));
        }
        else if (logfile)
            memcpy(g_pLogFile, logfile, sizeof(g_pLogFile));

        if (CommandLine()->CheckParm("-vxlpath") == NULL)
        {
            TCHAR lpTempPathBuffer[MAX_PATH];
            GetTempPath(MAX_PATH, lpTempPathBuffer);
            CommandLine()->AppendParm("-vxlpath", lpTempPathBuffer);
        }

        const char* pingboost;
        if (CommandLine()->CheckParm("-pingboost", &pingboost) && pingboost)
            g_iPingBoost = atoi(pingboost);

        HLDS_Log("=== Resolved params: port=%d, logfile='%s', pingboost=%d ===", g_iPort, g_pLogFile, g_iPingBoost);
        HLDS_Log("Full processed cmdline: %s", CommandLine()->GetCmdLine());

        HLDS_Log("LoadFilesystemModule...");
        HINTERFACEMODULE hFileSystem = LoadFilesystemModule();
        if (!hFileSystem)
        {
            HLDS_Log("FATAL: LoadFilesystemModule failed!");
            return LAUNCHER_ERROR;
        }
        HLDS_Log("LoadFilesystemModule OK: %p", hFileSystem);

        CreateInterfaceFn fsCreateInterface = (CreateInterfaceFn)Sys_GetFactory(hFileSystem);
        g_pFileSystem = (IFileSystem*)fsCreateInterface(FILESYSTEM_INTERFACE_VERSION, NULL);
        HLDS_Log("g_pFileSystem = %p", g_pFileSystem);
        g_pFileSystem->Mount();
        g_pFileSystem->AddSearchPath(Sys_GetLongPathName(), "BIN");
        HLDS_Log("FileSystem mounted. BIN path = '%s'", Sys_GetLongPathName());

        const char* pszEngineDLL = "hw.dll";
        HLDS_Log("Loading engine DLL: %s", pszEngineDLL);

        HINTERFACEMODULE hEngine;
        hEngine = Sys_LoadModule(pszEngineDLL);
        if (!hEngine)
        {
            HLDS_Log("FATAL: Could not load %s!", pszEngineDLL);
            static char msg[512];
            wsprintf(msg, "Could not load engine : %s.", pszEngineDLL);
            MessageBox(NULL, msg, "Fatal Error", MB_ICONERROR);
            return LAUNCHER_ERROR;
        }
        HLDS_Log("Engine DLL loaded: hEngine=%p", hEngine);

        CreateInterfaceFn engineCreateInterface = (CreateInterfaceFn)Sys_GetFactoryThis();
        HLDS_Log("engineCreateInterface = %p", engineCreateInterface);
        engineAPI = (IDedicatedServerAPI*)engineCreateInterface(VENGINE_HLDS_API_VERSION, NULL);
        HLDS_Log("engineAPI = %p", engineAPI);

        if (!engineCreateInterface || !engineAPI)
        {
            HLDS_Log("FATAL: engineCreateInterface=%p, engineAPI=%p", engineCreateInterface, engineAPI);
            return LAUNCHER_ERROR;
        }

        HLDS_Log("Calling Hook()...");
        Hook((HMODULE)hEngine);
        HLDS_Log("Hook() OK");

        // Log all pattern find results
        HLDS_Log("--- Pattern search results ---");
        HLDS_Log("g_pIsDedicated      = 0x%08X", g_pIsDedicated);
        HLDS_Log("g_pDediInitDword2   = 0x%08X", g_pDediInitDword2);
        HLDS_Log("g_pBaseSocket       = 0x%08X", g_pBaseSocket);
        HLDS_Log("g_pPacketHostServer = %p",      (void*)g_pPacketHostServer);
        HLDS_Log("g_pDediInitDword5   = %p",      (void*)g_pDediInitDword5);
        HLDS_Log("g_pDediInitDword6   = %p",      (void*)g_pDediInitDword6);
        HLDS_Log("g_pDediInitDwordExport = %p",   g_pDediInitDwordExport);
        HLDS_Log("g_pDediInitDword8   = 0x%08X",  g_pDediInitDword8);
        HLDS_Log("g_pServerState      = 0x%08X",  g_pServerState);
        HLDS_Log("g_pfnDediInitFunc1  = %p",      (void*)g_pfnDediInitFunc1);
        HLDS_Log("g_pfnDediInitFunc2  = %p",      (void*)g_pfnDediInitFunc2);
        HLDS_Log("g_pfnDediInitFunc3  = %p",      (void*)g_pfnDediInitFunc3);
        HLDS_Log("g_pfnDediInitFunc5  = %p",      (void*)g_pfnDediInitFunc5);
        HLDS_Log("g_pfnDediInitFunc6  = %p",      (void*)g_pfnDediInitFunc6);
        HLDS_Log("g_pfnDediInitFunc7  = %p",      (void*)g_pfnDediInitFunc7);
        HLDS_Log("g_pfnDediInitFunc8  = %p",      (void*)g_pfnDediInitFunc8);
        HLDS_Log("g_pfnDediInitFunc9  = %p",      (void*)g_pfnDediInitFunc9);
        HLDS_Log("g_pfnDediInitFunc10 = %p",      (void*)g_pfnDediInitFunc10);
        HLDS_Log("g_pCEngine          = %p",      (void*)g_pCEngine);
        HLDS_Log("g_pCGame            = %p",      (void*)g_pCGame);
        HLDS_Log("g_pCRegistry        = %p",      (void*)g_pCRegistry);
        HLDS_Log("g_pfnDediShutdown1  = %p",      (void*)g_pfnDediShutdownFunc1);
        HLDS_Log("g_pfnDediShutdown2  = %p",      (void*)g_pfnDediShutdownFunc2);
        HLDS_Log("------------------------------");

        HLDS_Log("Calling engineAPI->Init(basedir='%s')...", Sys_GetLongPathNameWithoutBin());
        if (!engineAPI->Init(Sys_GetLongPathNameWithoutBin(), CommandLine()->GetCmdLine(), Sys_GetFactoryThis(), fsCreateInterface))
        {
            HLDS_Log("FATAL: engineAPI->Init() returned false!");
            return LAUNCHER_ERROR;
        }
        HLDS_Log("engineAPI->Init() OK - server is running!");

        // Log what UDP ports HLDS is listening on
        HLDS_Log("Init complete. Check netstat for UDP port %d", g_iPort);

        if (g_iPingBoost == 4)
        {
            ULONG actualResolution;
            ZwSetTimerResolution(1, true, &actualResolution);
        }

        switch (g_iPingBoost)
        {
        case 4: sleep_thread = sleep_timer; break;
        case 5: sleep_thread = yield_thread; break;
        default: sleep_thread = sleep_1ms;
        }

        HLDS_Log("Entering main game loop (pingboost=%d)...", g_iPingBoost);

        bool done = false;
        while (!done)
        {
            sleep_thread();
            PrepareConsoleInput();
            if (g_bTerminated)
                break;
            ProcessConsoleInput();
            done = !engineAPI->RunFrame();
            UpdateStatus(FALSE);
        }

        HLDS_Log("Main loop exited. Shutting down...");
        int ret = engineAPI->Shutdown();
        HLDS_Log("Shutdown returned %d", ret);
        if (ret == DLL_CLOSE)
            g_bTerminated = true;

        Unhook();
        g_pFileSystem->Unmount();
        Sys_FreeModule(hFileSystem);
        Sys_FreeModule(hEngine);
        WSACleanup();
        HLDS_Log("Cleanup done. g_bTerminated=%d", g_bTerminated);
    } while (!g_bTerminated);

    HLDS_Log("=== HLDS main() EXIT ===");
    return LAUNCHER_OK;
}