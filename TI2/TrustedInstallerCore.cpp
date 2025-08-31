#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <userenv.h>
#include <string>
#include <iostream>
#include <vector>
#pragma comment(lib, "userenv.lib")

void Log(const std::wstring& msg) {
    std::wcout << L"[LOG] " << msg << std::endl;
}


bool EnableAllPrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::wcerr << L"[!] OpenProcessToken failed: " << GetLastError() << std::endl;
        return false;
    }

    DWORD size = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    PTOKEN_PRIVILEGES privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());

    if (!GetTokenInformation(hToken, TokenPrivileges, privileges, size, &size)) {
        std::wcerr << L"[!] GetTokenInformation failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
        LUID luid = privileges->Privileges[i].Luid;

        WCHAR name[256];
        DWORD nameLen = ARRAYSIZE(name);
        if (LookupPrivilegeNameW(NULL, &luid, name, &nameLen)) {
            std::wcout << L"[LOG] Enabling privilege: " << name << std::endl;
        }
        else {
            std::wcout << L"[LOG] Enabling privilege: (Unknown LUID)" << std::endl;
        }

        privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, privileges, 0, nullptr, nullptr)) {
        std::wcerr << L"[!] AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    DWORD err = GetLastError();
    CloseHandle(hToken);
    return err == ERROR_SUCCESS;
}
bool EnablePrivilege(LPCWSTR name) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;

    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
        CloseHandle(token);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    return result && GetLastError() == ERROR_SUCCESS;
}

DWORD FindProcessId(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry = { sizeof(entry) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

bool StartTrustedInstallerService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, L"TrustedInstaller", SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    StartServiceW(svc, 0, nullptr); // It's okay if it fails (already running)
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}
bool IsTokenTrustedInstaller(HANDLE hToken) {
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) return false;
    SID* sid = (SID*)((TOKEN_USER*)buffer.data())->User.Sid;

    LPWSTR sidStr = NULL;
    ConvertSidToStringSidW(sid, &sidStr);
    bool isTI = wcsstr(sidStr, L"S-1-5-80-956008885") != nullptr;
    LocalFree(sidStr);
    return isTI;
}
bool IsRunningAsSystem() {
    WCHAR name[256];
    DWORD size = 256;
    if (GetUserNameW(name, &size)) {
        return _wcsicmp(name, L"SYSTEM") == 0;
    }
    return false;
}
HANDLE GetTrustedInstallerToken() {
    Log(L"[*] Attempting to get TrustedInstaller token...");

    // Enable SeDebugPrivilege
    EnablePrivilege(SE_DEBUG_NAME);

    // Open service manager
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        Log(L"[!] OpenSCManager failed: " + std::to_wstring(GetLastError()));
        return NULL;
    }

    // Open TrustedInstaller service
    SC_HANDLE hService = OpenServiceW(hSCManager, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService) {
        Log(L"[!] OpenService failed: " + std::to_wstring(GetLastError()));
        CloseServiceHandle(hSCManager);
        return NULL;
    }

    // Query service status
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;

    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        Log(L"[!] QueryServiceStatusEx failed: " + std::to_wstring(GetLastError()));
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return NULL;
    }

    // If not running, start the service
    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        Log(L"[*] TrustedInstaller not running. Starting service...");
        if (!StartService(hService, 0, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                Log(L"[!] StartService failed: " + std::to_wstring(err));
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return NULL;
            }
        }

        // Wait for service to reach RUNNING
        Log(L"[*] Waiting for TrustedInstaller to start...");
        do {
            Sleep(500);
            if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                Log(L"[!] QueryServiceStatusEx failed while waiting: " + std::to_wstring(GetLastError()));
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return NULL;
            }
        } while (ssp.dwCurrentState == SERVICE_START_PENDING);
    }
    else {
        Log(L"[~] TrustedInstaller service is already running.");
    }

    DWORD tiPid = ssp.dwProcessId;
    Log(L"[+] TrustedInstaller PID: " + std::to_wstring(tiPid));

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    // Open process
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, tiPid);
    if (!hProc) {
        Log(L"[!] Failed to open TrustedInstaller.exe process: " + std::to_wstring(GetLastError()));
        return NULL;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        Log(L"[!] Failed to open token from TrustedInstaller.exe.");
        CloseHandle(hProc);
        return NULL;
    }

    HANDLE dupToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken)) {
        Log(L"[!] Failed to duplicate token.");
        CloseHandle(hToken);
        CloseHandle(hProc);
        return NULL;
    }

    CloseHandle(hToken);
    CloseHandle(hProc);
    Log(L"[+] Successfully duplicated TrustedInstaller token.");
    return dupToken;
}

bool LaunchAsTrustedInstaller(const std::wstring& cmd) {
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    EnablePrivilege(SE_INCREASE_QUOTA_NAME);

    HANDLE token = GetTrustedInstallerToken();
    if (!token) {
        Log(L"[!] Could not get TrustedInstaller token.");
        return false;
    }

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    SetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId));

    LPVOID env = nullptr;
    if (!CreateEnvironmentBlock(&env, token, FALSE)) {
        env = nullptr;
    }

    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    PROCESS_INFORMATION pi = {};
    BOOL result = CreateProcessAsUserW(
        token, nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
        env, nullptr, &si, &pi);


    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(token);

    if (!result) {
        Log(L"[!] Failed to launch process: " + std::to_wstring(GetLastError()));
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    Log(L"[+] Process launched as TrustedInstaller.");
    return true;
}
bool LaunchViaService(const std::wstring& exePath, const std::wstring& args) {
    std::wstring serviceName = L"TI2_TempSvc";

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        Log(L"[!] OpenSCManager failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    // Try to remove existing service
    SC_HANDLE hOld = OpenServiceW(hSCM, serviceName.c_str(), DELETE | SERVICE_STOP);
    if (hOld) {
        SERVICE_STATUS status = {};
        ControlService(hOld, SERVICE_CONTROL_STOP, &status);
        DeleteService(hOld);
        CloseServiceHandle(hOld);
        Sleep(1000);
    }

    std::wstring fullCmd = L"\"" + exePath + L"\" " + args;

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        fullCmd.c_str(),
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) {
        Log(L"[!] CreateService failed: " + std::to_wstring(GetLastError()));
        CloseServiceHandle(hSCM);
        return false;
    }

    Log(L"[+] Temporary service created.");

    if (!StartServiceW(hService, 0, NULL)) {
        Log(L"[!] StartService failed: " + std::to_wstring(GetLastError()));
        DeleteService(hService);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    Log(L"[+] Temporary service started. Waiting for elevation...");

    // Give the elevated process time to launch and duplicate the token
    Sleep(3000);

    DeleteService(hService);
    Log(L"[+] Temporary service deleted.");
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return true;
}
bool RunWithTiToken(const std::wstring& command) {
    if (!IsRunningAsSystem()) {
        std::wstring path(MAX_PATH, 0);
        GetModuleFileNameW(NULL, &path[0], MAX_PATH);
        path.resize(wcslen(path.c_str()));
        std::wstring args = L"--elevated \"" + command + L"\"";
        return LaunchViaService(path, args);
    }

    return LaunchAsTrustedInstaller(command);
}

int wmain(int argc, wchar_t* argv[]) {
    Log(L"Started app");

    EnableAllPrivileges(); 

    if (argc >= 2 && _wcsicmp(argv[1], L"--elevated") == 0) {
        // We are SYSTEM now, continue to TI logic
        std::wstring cmd;
        for (int i = 2; i < argc; ++i) {
            if (i > 2) cmd += L" ";
            cmd += argv[i];
        }
        LaunchAsTrustedInstaller(cmd);
        return 0;
    }

    if (!IsRunningAsSystem()) {
        Log(L"[~] Not running as SYSTEM. Elevating...");

        // Rebuild command line for SYSTEM-elevated run
        std::wstring fullPath(MAX_PATH, 0);
        GetModuleFileNameW(NULL, &fullPath[0], MAX_PATH);
        fullPath.resize(wcslen(fullPath.c_str()));

        std::wstring args = L"--elevated";
        for (int i = 1; i < argc; ++i) {
            args += L" \"" + std::wstring(argv[i]) + L"\"";
        }

        return LaunchViaService(fullPath, args) ? 0 : 1;
    }

    Log(L"[~] Already running as SYSTEM.");
    // Fall-through for debug if needed
    return 0;
}
