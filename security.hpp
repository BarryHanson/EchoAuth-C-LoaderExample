#pragma once

#include <string>
#include <vector>

namespace echoauth {

class Security {
public:
    /**
     * Check if process is being debugged
     */
    static bool is_debugged();

    /**
     * Check if running as admin
     */
    static bool is_elevated();

    /**
     * Check memory integrity
     * Detects if code sections have been modified
     */
    static bool verify_memory_integrity();

    /**
     * Obfuscate/deobfuscate strings at runtime
     * Used to hide sensitive strings from static analysis
     */
    static std::string obfuscate_string(const std::string& str, uint32_t key);
    static std::string deobfuscate_string(const std::string& obfuscated, uint32_t key);

    /**
     * Clear sensitive data from memory
     * Overwrites with random values before freeing
     */
    static void secure_free(void* ptr, size_t size);

    template<typename T>
    static void secure_clear(T& container) {
        if (!container.empty()) {
            secure_free((void*)container.data(), container.size());
            container.clear();
        }
    }

    /**
     * Get process environment checksum
     * Used to detect if process has been tampered with
     */
    static uint32_t get_environment_checksum();

    /**
     * Calculate module checksum (for integrity verification)
     */
    static uint32_t calculate_module_checksum();

private:
    static constexpr uint32_t MAGIC_KEY = 0xDEADBEEF;
};

} // namespace echoauth
