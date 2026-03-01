#include <windows.h>
#include "HLSDK/common/interface.h"
#include "ICommandLine.h"
#include "IFileSystem.h"
#include "sys.h"
#include "hook.h"
#include <stdio.h>
#include <thread>
#include <chrono>
#include <string>
#include <vector>

// ──────────────────────────────────────────────────────────────────────────
// -useful / -usexternaldll <dll>  parameter support
//
// Loads one or more DLLs before the engine initialises, giving them time
// to install hooks (e.g. a LoadLibraryA hook that patches mp.dll vtables).
//
// Usage:
//   hlds.exe -usexternaldll weaponfix.dll -game czero +maxplayers 32
//   hlds.exe -usexternaldll a.dll -usexternaldll b.dll -game czero
//   hlds.exe -useful "path with spaces\fix.dll" -game czero
// ──────────────────────────────────────────────────────────────────────────

// Parse every -useful <path> or -usexternaldll <path> pair from the raw
// Win32 command-line string.
// Must be called on the raw string BEFORE CommandLine()->CreateCmdLine().
static std::vector<std::string> ParseUsefulDlls(const char* cmdline)
{
    std::vector<std::string> out;
    if (!cmdline) return out;

    // Both flags load a DLL the same way; -usexternaldll is the CSNZ convention.
    static const struct { const char* flag; int len; } flags[] = {
        { "-useful",        7 },
        { "-usexternaldll", 15 },
    };

    const char* p = cmdline;
    while (*p)
    {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;

        bool matched = false;
        for (auto& f : flags)
        {
            if (_strnicmp(p, f.flag, f.len) == 0 &&
                (p[f.len] == ' ' || p[f.len] == '\t' || p[f.len] == '\0'))
            {
                p += f.len;
                while (*p == ' ' || *p == '\t') ++p;
                if (!*p) goto done;
                std::string path;
                if (*p == '"') {
                    ++p;
                    while (*p && *p != '"') path += *p++;
                    if (*p == '"') ++p;
                } else {
                    while (*p && *p != ' ' && *p != '\t') path += *p++;
                }
                if (!path.empty()) out.push_back(path);
                matched = true;
                break;
            }
        }

        if (!matched)
        {
            if (*p == '"') { ++p; while (*p && *p != '"') ++p; if (*p) ++p; }
            else           { while (*p && *p != ' ' && *p != '\t') ++p; }
        }
    }
done:
    return out;
}

// Load each DLL and log result.
static void LoadUsefulDlls(const std::vector<std::string>& dlls)
{
    for (const auto& path : dlls) {
        HMODULE h = LoadLibraryA(path.c_str());
        if (h)
            printf("[HLDS] -usexternaldll/useful: loaded '%s' @ %p\n", path.c_str(), (void*)h);
        else
            printf("[HLDS] -usexternaldll/useful: FAILED to load '%s' (GetLastError=%lu)\n", path.c_str(), GetLastError());
        fflush(stdout);
    }
}

// Strip all -useful and -usexternaldll <value> pairs so the engine never
// sees unknown flags. RemoveParm removes the flag and its next token.
static void StripUsefulParams()
{
    while (CommandLine()->CheckParm("-useful"))
        CommandLine()->RemoveParm("-useful");
    while (CommandLine()->CheckParm("-usexternaldll"))
        CommandLine()->RemoveParm("-usexternaldll");
}

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


#define LOG(fmt, ...) do { printf("[HLDS] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while(0)
char g_pLogFile[MAX_PATH];
char g_pConsoleTitle[MAX_PATH];
int g_iPort = 27015;

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
        LOG("Init() start");
        *(IDedicatedExports**)g_pDediInitDwordExport = (IDedicatedExports*)launcherFactory(VENGINE_DEDICATEDEXPORTS_API_VERSION, nullptr);
        LOG("IDedicatedExports = %p", *(IDedicatedExports**)g_pDediInitDwordExport);
        if (!*(IDedicatedExports**)g_pDediInitDwordExport)
        { LOG("FATAL: IDedicatedExports NULL"); return false; }

        strncpy(this->m_OrigCmd, cmdline, ARRAYSIZE(this->m_OrigCmd));
        this->m_OrigCmd[ARRAYSIZE(this->m_OrigCmd) - 1] = 0;

        LOG("DediInitFunc1 Sys_InitArgv...");
        g_pfnDediInitFunc1("Sys_InitArgv( m_OrigCmd )", "Sys_ShutdownArgv()", 0);
        LOG("DediInitFunc1 OK");
        LOG("DediInitFunc2 ParseCmdLine...");
        g_pfnDediInitFunc2(this->m_OrigCmd);
        LOG("DediInitFunc2 OK");
        LOG("SetQuitting(0)...");
        g_pCEngine->SetQuitting(0);
        //g_pCRegistry->Init();
        LOG("SetQuitting OK");
        g_pIsDedicated = true;

        LOG("DediInitFunc1 FileSystem_Init...");
        g_pfnDediInitFunc1("FileSystem_Init(basedir, (void *)filesystemFactory)", "FileSystem_Shutdown()", 0);
        LOG("DediInitFunc1 FileSystem OK");
        LOG("DediInitFunc3 (FileSystem init) basedir=%s...", basedir);
        if (!g_pfnDediInitFunc3(basedir, (void*)filesystemFactory))
        { LOG("FATAL: DediInitFunc3 failed"); return false; }
        LOG("DediInitFunc3 OK");
        LOG("CGame::CreateWin()...");
        g_pCGame->CreateWin();
        LOG("CGame::CreateWin OK");
        LOG("CGame::Init(nullptr)...");
        if (!g_pCGame->Init(nullptr))
        { LOG("FATAL: CGame::Init failed"); return false; }
        LOG("CGame::Init OK");
        char buffer[MAX_PATH];
        __time64_t currentTime = 0;
        currentTime = _time64(NULL);

        struct tm localTime;
        _localtime64_s(&localTime, &currentTime);

        DWORD pid = GetCurrentProcessId();
        g_pfnDediInitFunc5(buffer, "%s_%04d%02d%02d_%02d%02d%02d_%u_%d.log", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);
        g_pfnDediInitFunc5(g_pDediInitDword5, "%sFatal_%04d%02d%02d_%02d%02d%02d_%u_%d.log", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);
        g_pfnDediInitFunc5(g_pDediInitDword6, "%s_##ADDR##_%04d%02d%02d_%02d%02d%02d_%u.dmp", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);

        snprintf(g_pConsoleTitle, sizeof(g_pConsoleTitle), "%s_%04d%02d%02d_%02d%02d%02d_%u_%d", g_pLogFile, localTime.tm_year + 1900, localTime.tm_mon + 1, localTime.tm_mday, localTime.tm_hour, localTime.tm_min, localTime.tm_sec, pid, g_iPort);

        LOG("DediInitFunc8 (init log) buffer=%s...", buffer);
        g_pfnDediInitFunc8(buffer, 0, 0);
        LOG("DediInitFunc8 OK");

        void* hwnd = g_pCGame->Func24();
        LOG("HWND=%p", hwnd);
        LOG("DediInitFunc6...");
        g_pfnDediInitFunc6(hwnd);
        LOG("DediInitFunc6 OK");

        LOG("Setting BaseSocket HWND... g_pBaseSocket=0x%08X", g_pBaseSocket);
        *(DWORD**)(*(DWORD*)g_pBaseSocket + 0xC) = (DWORD*)g_pCGame->Func24();
        LOG("BaseSocket HWND set OK");
        LOG("CGame::Shutdown()...");
        g_pCGame->Shutdown();
        LOG("CGame::Shutdown OK");

        LOG("DediInitFunc10...");
        g_pfnDediInitFunc10(buffer);
        g_pfnDediInitFunc10(g_pDediInitDword5);
        LOG("DediInitFunc10 OK");

        LOG("CEngine::Load(true, basedir, cmdline)...");
        if (!g_pCEngine->Load(true, basedir, cmdline))
        { LOG("FATAL: CEngine::Load failed"); return false; }
        LOG("CEngine::Load OK");

        //char text[256];
        //snprintf(text, ARRAYSIZE(text), "exec %s\n", "server.cfg");
        //text[255] = 0;
        LOG("DediInitFunc7 exec server.cfg...");
        g_pfnDediInitFunc7("exec server.cfg\n");
        LOG("DediInitFunc7 OK");

        LOG("g_pPacketHostServer=%p", (void*)g_pPacketHostServer);
        if (g_pPacketHostServer)
        {
            LOG("DediInitFunc9...");
            g_pfnDediInitFunc9(g_pPacketHostServer, buffer);
            LOG("DediInitFunc9 OK");
        }
        LOG("Init() COMPLETE returning true");
        return true;
    };
    int Shutdown()
    {
        g_pCEngine->Unload();
        g_pCGame->DestroyWin();
        g_pfnDediShutdownFunc1("FileSystem_Shutdown()", 0);
        g_pfnDediShutdownFunc2();
        //g_pCRegistry->RegClose();
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

#define DEFAULT_IP "127.0.0.1"
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
    LOG("=== main() START === cmdline: %s", GetCommandLine());
    g_bTerminated = false;

    do {
        // ── Load -useful DLLs BEFORE CreateCmdLine ────────────────────────
        // Parse from raw Win32 cmdline while it's still unmodified.
        // Each DLL's DllMain runs here, before the engine or mp.dll loads.
        {
            auto usefulDlls = ParseUsefulDlls(GetCommandLineA());
            if (!usefulDlls.empty()) LoadUsefulDlls(usefulDlls);
        }

        CommandLine()->CreateCmdLine(GetCommandLine());

        // Strip -useful pairs so the engine never sees unknown parameters.
        StripUsefulParams();

        CommandLine()->RemoveParm("-steam");
        CommandLine()->AppendParm("-console", nullptr);

        WSAData WSAData;
        WSAStartup(0x202, &WSAData);

        if (CommandLine()->CheckParm("-lang") == NULL)
            CommandLine()->AppendParm("-lang", "na_"); 	// the dedicated server won't load without this line

        if (CommandLine()->CheckParm("-ip") == NULL)
            CommandLine()->AppendParm("-ip", DEFAULT_IP);

        if (CommandLine()->CheckParm("-lobbyport") == NULL)
            CommandLine()->AppendParm("-lobbyport", DEFAULT_LOBBYPORT);

        const char* port;
        if (CommandLine()->CheckParm("-port", &port) == NULL)
        {
            CommandLine()->AppendParm("-port", DEFAULT_PORT);
            g_iPort = atoi(DEFAULT_PORT);
        }
        else if (port)
            g_iPort = atoi(port);

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

        HINTERFACEMODULE hFileSystem = LoadFilesystemModule();

        if (!hFileSystem)
            return LAUNCHER_ERROR;

        CreateInterfaceFn fsCreateInterface = (CreateInterfaceFn)Sys_GetFactory(hFileSystem);
        g_pFileSystem = (IFileSystem*)fsCreateInterface(FILESYSTEM_INTERFACE_VERSION, NULL);
        g_pFileSystem->Mount();
        g_pFileSystem->AddSearchPath(Sys_GetLongPathName(), "BIN");

        const char* pszEngineDLL = "hw.dll";

        HINTERFACEMODULE hEngine;

        hEngine = Sys_LoadModule(pszEngineDLL);
        if (!hEngine)
        {
            static char msg[512];
            wsprintf(msg, "Could not load engine : %s.", pszEngineDLL);
            MessageBox(NULL, msg, "Fatal Error", MB_ICONERROR);
            return LAUNCHER_ERROR;
        }

        CreateInterfaceFn engineCreateInterface = (CreateInterfaceFn)Sys_GetFactoryThis();
        engineAPI = (IDedicatedServerAPI*)engineCreateInterface(VENGINE_HLDS_API_VERSION, NULL);

        if (!engineCreateInterface || !engineAPI)
            return LAUNCHER_ERROR;

        LOG("Calling Hook()...");
        Hook((HMODULE)hEngine);
        LOG("Hook() done. Calling engineAPI->Init()...");

        if (!engineAPI->Init(Sys_GetLongPathNameWithoutBin(), CommandLine()->GetCmdLine(), Sys_GetFactoryThis(), fsCreateInterface))
        { LOG("FATAL: engineAPI->Init() returned false"); return LAUNCHER_ERROR; }
        LOG("engineAPI->Init() OK - entering main loop");

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

        LOG("Entering main loop...");
        bool done = false;
        int frameNum = 0;
        while (!done)
        {
            sleep_thread();
            PrepareConsoleInput();
            if (g_bTerminated) { LOG("g_bTerminated at frame %d", frameNum); break; }
            ProcessConsoleInput();
            bool rf = engineAPI->RunFrame();
            if (!rf) LOG("RunFrame() FALSE at frame %d, GetQuitting=%d", frameNum, g_pCEngine->GetQuitting());
            done = !rf;
            if (frameNum < 3) LOG("Frame %d OK", frameNum);
            frameNum++;
            UpdateStatus(FALSE);
        }
        LOG("Main loop exited at frame %d", frameNum);

        LOG("Shutdown()...");
        int ret = engineAPI->Shutdown();
        LOG("Shutdown() returned %d", ret);
        if (ret == DLL_CLOSE)
            g_bTerminated = true;

        Unhook();

        g_pFileSystem->Unmount();

        Sys_FreeModule(hFileSystem);
        Sys_FreeModule(hEngine);

        WSACleanup();
    } while (!g_bTerminated);

    return LAUNCHER_OK;
}
