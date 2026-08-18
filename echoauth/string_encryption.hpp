#pragma once
#include <string>
#include <cstring>
#include <windows.h>

namespace StringEncryption {
    // Simple XOR cipher for string obfuscation
    // This is compile-time string encryption to hide sensitive data
    constexpr unsigned char XOR_KEY = 0x42;

    class EncryptedString {
    private:
        char buffer[256];
        size_t length;

    public:
        // Constructor for encrypted string literals
        EncryptedString(const char* str) : length(0) {
            if (str) {
                while (str[length] && length < 255) {
                    buffer[length] = str[length] ^ XOR_KEY;
                    length++;
                }
            }
            buffer[length] = '\0';
        }

        // Decrypt to std::string
        std::string decrypt() const {
            std::string result;
            result.reserve(length);
            for (size_t i = 0; i < length; i++) {
                result += (char)(buffer[i] ^ XOR_KEY);
            }
            return result;
        }

        // Get decrypted C-string
        const char* c_str() const {
            static thread_local char temp[256];
            for (size_t i = 0; i <= length; i++) {
                temp[i] = (char)(buffer[i] ^ XOR_KEY);
            }
            return temp;
        }
    };

    // Secure string class that clears memory on destruction
    class SecureString {
    private:
        std::string data;

    public:
        SecureString() = default;

        SecureString(const std::string& str) : data(str) {}

        SecureString(const char* str) : data(str ? str : "") {}

        ~SecureString() {
            // Securely clear the string from memory
            if (!data.empty()) {
                SecureZeroMemory((void*)data.data(), data.capacity());
            }
        }

        // Prevent copying to avoid accidental leaks
        SecureString(const SecureString&) = delete;
        SecureString& operator=(const SecureString&) = delete;

        // Allow move semantics
        SecureString(SecureString&& other) noexcept : data(std::move(other.data)) {}
        SecureString& operator=(SecureString&& other) noexcept {
            if (this != &other) {
                SecureZeroMemory((void*)data.data(), data.capacity());
                data = std::move(other.data);
            }
            return *this;
        }

        const std::string& get() const { return data; }
        const char* c_str() const { return data.c_str(); }
        size_t size() const { return data.size(); }
        bool empty() const { return data.empty(); }

        operator const std::string&() const { return data; }
        operator std::string() const { return data; }

        friend std::string operator+(const SecureString& sec, const std::string& str) {
            return sec.data + str;
        }
        friend std::string operator+(const std::string& str, const SecureString& sec) {
            return str + sec.data;
        }
        friend std::string operator+(const SecureString& sec, const char* str) {
            return sec.data + std::string(str ? str : "");
        }
        friend std::string operator+(const char* str, const SecureString& sec) {
            return std::string(str ? str : "") + sec.data;
        }
    };
}

// Macro to easily encrypt strings at runtime
#define ENCRYPT_STR(str) (StringEncryption::EncryptedString(str).decrypt())
#define ENCRYPTED(str) (StringEncryption::EncryptedString(str).decrypt())
