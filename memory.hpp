#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace echoauth {

class MemoryExecutor {
public:
    /**
     * Execute PE binary directly from memory without writing to disk
     * @param pe_data Raw PE executable data
     * @param command_line Command line arguments for the process
     * @return Process ID of created process, or 0 on failure
     */
    static uint32_t execute_from_memory(
        const std::vector<uint8_t>& pe_data,
        const std::string& command_line = ""
    );

    /**
     * Execute PE binary using shellcode injection
     * @param pe_data Raw PE executable data
     * @param target_pid Target process ID (0 = create new)
     * @return Process ID where injection occurred
     */
    static uint32_t execute_via_injection(
        const std::vector<uint8_t>& pe_data,
        uint32_t target_pid = 0
    );

    /**
     * Validate PE binary structure
     * @param pe_data PE binary data to validate
     * @return true if valid PE header and structure
     */
    static bool validate_pe_header(const std::vector<uint8_t>& pe_data);

    /**
     * Get entry point from PE binary
     * @param pe_data PE binary data
     * @return Relative entry point address, or 0 on error
     */
    static uint32_t get_entry_point(const std::vector<uint8_t>& pe_data);

    /**
     * Allocate executable memory with specified protection
     * @param size Size of memory to allocate
     * @param executable Whether memory should be executable
     * @return Pointer to allocated memory
     */
    static void* allocate_executable_memory(size_t size, bool executable = true);

    /**
     * Free allocated memory securely
     * @param ptr Pointer to memory to free
     * @param size Size to overwrite with random data
     */
    static void free_executable_memory(void* ptr, size_t size);

private:
    /**
     * Windows-specific PE loader
     */
    static uint32_t load_pe_windows(const std::vector<uint8_t>& pe_data);

    /**
     * Fix PE imports and relocations
     */
    static bool fix_relocations(void* base_address, const std::vector<uint8_t>& pe_data);
};

} // namespace echoauth
