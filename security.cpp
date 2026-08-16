#include "security.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <cstdint>
#include <algorithm>
#include <cctype>
#include <string>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace echoauth {

// ============================================================================
// Debugger Detection
// ============================================================================

bool Security::is_debugged() {
    return IsDebuggerPresent() != FALSE;
}

// ============================================================================
// Privilege Elevation Check
// ============================================================================

bool Security::is_elevated() {
    BOOL fRun = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        CloseHandle(hToken);
        return false;
    }

    fRun = (elevation.TokenIsElevated != 0);
    CloseHandle(hToken);

    return fRun;
}

// ============================================================================
// Memory Integrity Checks
// ============================================================================

bool Security::verify_memory_integrity() {
    // Get current module handle
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) {
        return false;
    }

    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return false;
    }

    // Calculate checksum of code sections
    DWORD dwChecksum = 0;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader);

    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i) {
        if ((pSection[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
            (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

            BYTE* pSectionData = (BYTE*)hModule + pSection[i].VirtualAddress;
            for (DWORD j = 0; j < pSection[i].SizeOfRawData; ++j) {
                dwChecksum = ((dwChecksum << 5) + dwChecksum) + pSectionData[j];
            }
        }
    }

    // In a real implementation, you'd compare against a known good checksum
    // This is a simplified version
    return dwChecksum != 0;
}

// ============================================================================
// String Obfuscation
// ============================================================================

std::string Security::obfuscate_string(const std::string& str, uint32_t key) {
    std::string result = str;
    for (size_t i = 0; i < result.length(); ++i) {
        uint32_t keyByte = (key >> ((i % 4) * 8)) & 0xFF;
        result[i] ^= keyByte;
    }
    return result;
}

std::string Security::deobfuscate_string(const std::string& obfuscated, uint32_t key) {
    // XOR is symmetric
    return obfuscate_string(obfuscated, key);
}

// ============================================================================
// Secure Memory Clearing
// ============================================================================

void Security::secure_free(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    // Overwrite with random data before freeing
    SecureZeroMemory(ptr, size);
}

// ============================================================================
// Environment Checksum
// ============================================================================

uint32_t Security::get_environment_checksum() {
    uint32_t checksum = 0;

    // Hash various environment indicators
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    checksum ^= sysInfo.dwNumberOfProcessors;

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    checksum ^= static_cast<uint32_t>(memStatus.ullTotalPhys >> 32);

    // Hash running processes
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(hProcessSnap, &pe32)) {
            do {
                for (wchar_t c : pe32.szExeFile) {
                    checksum = ((checksum << 5) + checksum) + c;
                }
            } while (Process32NextW(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }

    return checksum;
}

// ============================================================================
// Module Checksum
// ============================================================================

uint32_t Security::calculate_module_checksum() {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) {
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);

    uint32_t checksum = 0;
    BYTE* pData = (BYTE*)hModule;

    // Checksum only .text section for performance
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader);
    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            BYTE* pSectionData = pData + pSection[i].VirtualAddress;
            for (DWORD j = 0; j < pSection[i].SizeOfRawData; ++j) {
                checksum = ((checksum << 5) + checksum) + pSectionData[j];
            }
            break;
        }
    }

    return checksum;
}

} // namespace echoauth
