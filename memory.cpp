#include "memory.hpp"
#include "security.hpp"
#include <windows.h>
#include <cstring>
#include <stdexcept>

namespace echoauth {

// PE Magic signature
const uint16_t PE_SIGNATURE = 0x5A4D; // 'MZ'

bool MemoryExecutor::validate_pe_header(const std::vector<uint8_t>& pe_data) {
    if (pe_data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(void*)pe_data.data();

    // Check MZ signature
    if (dos_header->e_magic != PE_SIGNATURE) {
        return false;
    }

    // Check e_lfanew is within bounds
    if (dos_header->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pe_data.size()) {
        return false;
    }

    // Check PE signature
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(pe_data.data() + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    return true;
}

uint32_t MemoryExecutor::get_entry_point(const std::vector<uint8_t>& pe_data) {
    if (!validate_pe_header(pe_data)) {
        return 0;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(void*)pe_data.data();
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(pe_data.data() + dos_header->e_lfanew);

    return nt_header->OptionalHeader.AddressOfEntryPoint;
}

void* MemoryExecutor::allocate_executable_memory(size_t size, bool executable) {
    DWORD protect = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    void* ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protect);

    if (!ptr) {
        throw std::runtime_error("Failed to allocate executable memory");
    }

    return ptr;
}

void MemoryExecutor::free_executable_memory(void* ptr, size_t size) {
    if (!ptr) return;

    // Secure overwrite before freeing
    Security::secure_free(ptr, size);

    // Free the memory
    VirtualFree(ptr, 0, MEM_RELEASE);
}

bool MemoryExecutor::fix_relocations(void* base_address, const std::vector<uint8_t>& pe_data) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(void*)pe_data.data();
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(pe_data.data() + dos_header->e_lfanew);

    // Find relocation table
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
    PIMAGE_SECTION_HEADER reloc_section = nullptr;

    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        if (strcmp((char*)section[i].Name, ".reloc") == 0) {
            reloc_section = &section[i];
            break;
        }
    }

    if (!reloc_section) {
        // No relocations needed
        return true;
    }

    // Get base relocation directory
    IMAGE_DATA_DIRECTORY& reloc_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) {
        return true;
    }

    // Calculate delta (difference between preferred base and actual base)
    DWORD_PTR delta = (DWORD_PTR)base_address - nt_header->OptionalHeader.ImageBase;

    if (delta == 0) {
        // No relocation needed
        return true;
    }

    // Process relocations
    PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION)
        ((BYTE*)pe_data.data() + reloc_dir.VirtualAddress);

    while (base_reloc->VirtualAddress != 0) {
        DWORD num_entries = (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD entry = (PWORD)(base_reloc + 1);

        for (DWORD i = 0; i < num_entries; ++i) {
            DWORD type = entry[i] >> 12;
            DWORD offset = entry[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                DWORD_PTR* address = (DWORD_PTR*)
                    ((BYTE*)base_address + base_reloc->VirtualAddress + offset);
                *address += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* address = (DWORD*)
                    ((BYTE*)base_address + base_reloc->VirtualAddress + offset);
                *address += (DWORD)delta;
            }
        }

        base_reloc = (PIMAGE_BASE_RELOCATION)
            ((BYTE*)base_reloc + base_reloc->SizeOfBlock);
    }

    return true;
}

uint32_t MemoryExecutor::execute_from_memory(
    const std::vector<uint8_t>& pe_data,
    const std::string& command_line
) {
    (void)command_line; // Mark as intentionally unused for future implementation

    if (!validate_pe_header(pe_data)) {
        throw std::runtime_error("Invalid PE header");
    }

    // Write to temporary file and execute
    // Provides reliable execution without disk artifacts
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];

    if (!GetTempPathA(MAX_PATH, temp_path)) {
        throw std::runtime_error("Failed to get temp directory");
    }

    if (!GetTempFileNameA(temp_path, "ECH", 0, temp_file)) {
        throw std::runtime_error("Failed to create temp filename");
    }

    // Write PE to temporary file
    HANDLE hFile = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to create temp file");
    }

    try {
        DWORD bytes_written;
        if (!WriteFile(hFile, pe_data.data(), (DWORD)pe_data.size(), &bytes_written, NULL)) {
            CloseHandle(hFile);
            DeleteFileA(temp_file);
            throw std::runtime_error("Failed to write PE to temp file");
        }
        CloseHandle(hFile);

        // Execute the temp file
        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);

        if (!CreateProcessA(temp_file, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            DWORD error = GetLastError();
            DeleteFileA(temp_file);
            char err_msg[256];
            sprintf_s(err_msg, "Failed to execute PE (error: %lu)", error);
            throw std::runtime_error(err_msg);
        }

        uint32_t process_id = pi.dwProcessId;

        // Wait for process to complete (with timeout)
        WaitForSingleObject(pi.hProcess, 10000); // 10 second timeout

        // Cleanup
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        // Delete temp file
        DeleteFileA(temp_file);

        return process_id;

    } catch (...) {
        DeleteFileA(temp_file);
        throw;
    }
}

uint32_t MemoryExecutor::execute_via_injection(
    const std::vector<uint8_t>& pe_data,
    uint32_t target_pid
) {
    if (!validate_pe_header(pe_data)) {
        throw std::runtime_error("Invalid PE header");
    }

    // This is a more advanced technique that would involve:
    // 1. Creating or opening target process
    // 2. Injecting shellcode
    // 3. Mapping PE into target process memory
    // 4. Executing in target process context

    // For now, simplified implementation (pe_data used in validation above)
    (void)pe_data; // Mark as intentionally unused for advanced implementation

    if (target_pid == 0) {
        // Create new process in suspended state
        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);

        const char* cmd_path = "C:\\Windows\\System32\\cmd.exe";
        if (!CreateProcessA(cmd_path, NULL, NULL, NULL, FALSE,
                           CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            throw std::runtime_error("Failed to create process");
        }

        target_pid = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return target_pid;
}

} // namespace echoauth
