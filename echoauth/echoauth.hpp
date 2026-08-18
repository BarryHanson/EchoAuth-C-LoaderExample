#pragma once

// Private library headers (implementation details)
#include "client.hpp"
#include "crypto.hpp"
#include "exceptions.hpp"
#include "response.hpp"
#include "memory.hpp"
#include "security.hpp"

#include <string>
#include <vector>

namespace EchoAuth {
    // Global client instance (initialized in main.cpp)
    extern echoauth::EchoAuthClient* g_client;

    // ===== Authentication =====
    inline echoauth::LoginResponse Login(const std::string& username, const std::string& password, const std::string& hwid = "") {
        if (!g_client) return echoauth::LoginResponse();
        return g_client->login(username, password, hwid);
    }

    inline void SetToken(const std::string& token) {
        if (g_client) g_client->set_token(token);
    }

    inline std::string GetToken() {
        if (!g_client) return "";
        return g_client->get_token();
    }

    // ===== Loader Operations =====
    inline bool CheckVersion(int loader_id, const std::string& version, const std::string& filename) {
        if (!g_client) return false;
        return g_client->check_loader_version(loader_id, version, filename);
    }

    inline echoauth::CheatFileDownloadResponse DownloadCheat(int cheat_id, const std::string& xor_key) {
        if (!g_client) return echoauth::CheatFileDownloadResponse();
        return g_client->download_cheat_validated(cheat_id, xor_key);
    }

    // ===== Security & Logging =====
    inline bool Ban(const std::string& username, const std::string& hwid, const std::string& reason) {
        if (!g_client) return false;
        return g_client->ban_account(username, hwid, reason);
    }

    inline bool Log(const std::string& message, const std::string& level) {
        if (!g_client) return false;
        return g_client->log_event(message, level);
    }

    // ===== Direct Crypto/Utility Access (if needed) =====
    inline std::vector<unsigned char> XorEncrypt(const std::vector<unsigned char>& data, const std::string& key) {
        return echoauth::Crypto::xor_encrypt(data, key);
    }

    inline bool ValidatePEHeader(const std::vector<unsigned char>& data) {
        return echoauth::MemoryExecutor::validate_pe_header(data);
    }

    inline void ExecuteFromMemory(const std::vector<unsigned char>& data, const std::string& args) {
        echoauth::MemoryExecutor::execute_from_memory(data, args);
    }

    inline bool IsDebugger() {
        return echoauth::Security::is_debugged();
    }

    inline bool IsElevated() {
        return echoauth::Security::is_elevated();
    }

    inline void SecureClear(std::vector<unsigned char>& data) {
        echoauth::Security::secure_clear(data);
    }
}
