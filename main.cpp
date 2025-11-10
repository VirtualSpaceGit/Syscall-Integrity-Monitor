#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "wintrust.lib")

struct SyscallPattern {
    BYTE pattern[16];
    size_t length;
    std::string name;
};

std::vector<SyscallPattern> GetCommonSyscallPatterns() {
    std::vector<SyscallPattern> patterns;
    
    SyscallPattern pattern1 = { {0x4C, 0x8B, 0xD1, 0xB8}, 4, "MOV R10, RCX; MOV EAX" };
    patterns.push_back(pattern1);
    
    SyscallPattern pattern2 = { {0x0F, 0x05}, 2, "SYSCALL" };
    patterns.push_back(pattern2);
    
    SyscallPattern pattern3 = { {0x49, 0x89, 0xCA, 0xB8}, 4, "MOV R10, RCX (alternate); MOV EAX" };
    patterns.push_back(pattern3);
    
    return patterns;
}

bool IsFileSigned(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    WINTRUST_DATA trustData;
    memset(&trustData, 0, sizeof(trustData));
    trustData.cbStruct = sizeof(trustData);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileInfo;

    LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return (result == ERROR_SUCCESS);
}

std::wstring GetProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return L"";
    
    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return std::wstring(path);
    }
    
    CloseHandle(hProcess);
    return L"";
}

bool ContainsSyscallPattern(BYTE* buffer, size_t size) {
    auto patterns = GetCommonSyscallPatterns();
    
    for (size_t i = 0; i < size - 16; i++) {
        bool foundMovPattern = false;
        bool foundSyscall = false;
        
        if (buffer[i] == 0x4C && buffer[i + 1] == 0x8B && buffer[i + 2] == 0xD1 && buffer[i + 3] == 0xB8) {
            foundMovPattern = true;
        }
        
        if (buffer[i] == 0x49 && buffer[i + 1] == 0x89 && buffer[i + 2] == 0xCA && buffer[i + 3] == 0xB8) {
            foundMovPattern = true;
        }
        
        if (foundMovPattern) {
            for (size_t j = i; j < min(i + 32, size - 2); j++) {
                if (buffer[j] == 0x0F && buffer[j + 1] == 0x05) {
                    foundSyscall = true;
                    break;
                }
            }
        }
        
        if (foundMovPattern && foundSyscall) {
            return true;
        }
    }
    
    return false;
}

void ScanProcess(DWORD pid, const std::string& processName) {
    // Signed apps excluded
    std::wstring processPath = GetProcessPath(pid);
    if (processPath.empty()) return;
    
    if (IsFileSigned(processPath)) {
        return;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* address = 0;
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                if (ContainsSyscallPattern(buffer.data(), bytesRead)) {
                    SYSTEMTIME st;
                    GetLocalTime(&st);
                    
                    printf("[!] DIRECT SYSCALL DETECTED [%02d:%02d:%02d] %s (PID: %lu) at 0x%p\n",
                           st.wHour, st.wMinute, st.wSecond,
                           processName.c_str(), pid, mbi.BaseAddress);
                }
            }
        }
        
        address += mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
}

void MonitorSyscalls() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::string processName = pe32.szExeFile;
            
            if (processName != "System" && processName != "Idle" && processName != "Registry") {
                ScanProcess(pe32.th32ProcessID, processName);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

int main() {
    std::cout << "VirtualSpace Syscall Integrity Monitor\n";
    std::cout << "Monitoring for direct syscall usage patterns...\n";
    std::cout << "Signed applications excluded from scanning\n\n";
    
    while (true) {
        MonitorSyscalls();
        Sleep(5000);
    }
    return 0;
}
