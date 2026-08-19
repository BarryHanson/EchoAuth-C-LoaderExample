#define _CRT_SECURE_NO_WARNINGS

#include "echoauth/echoauth.hpp"
#include "echoauth/client.hpp"
#include "security.hpp"
#include "memory.hpp"
#include "echoauth/string_encryption.hpp"
#include "echoauth/process_monitor.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <windows.h>

// Global client for EchoAuth wrapper
echoauth::EchoAuthClient* EchoAuth::g_client = nullptr;


//Replace these values with your own from the EchoAuth dashboard
namespace Config {
	// Encrypted sensitive strings to hide from static analysis
	static std::string get_api_url() { return ENCRYPT_STR("http://62.72.7.120:3001"); }
	static std::string get_api_secret() { return ENCRYPT_STR("secret_a7544bad113a54f9dfcbe9729929b3091f70597003dd7b70e6e065d3c8148310"); }
	static std::string get_xor_key() { return ENCRYPT_STR("owner_enc_key_here"); }

    const int CHEAT_ID = 3;
    const int LOADER_ID = 1;
    const char* LOADER_VERSION = "1.0.0";
    const char* LOADER_FILENAME = "EchoAuthLoader.exe";
    const bool VERIFY_SSL = true;
}

//global variables to track authentication state and user info
static std::atomic<bool> g_authenticated(false);
static std::string g_username;
static std::string g_hwid;

//get the executable filename (without path) using Windows API for filename verification
std::string get_executable_filename() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string full_path(buffer);
    size_t last_slash = full_path.find_last_of("\\/");
    if (last_slash != std::string::npos) {
        return full_path.substr(last_slash + 1);
    }
    return full_path;
}


//get the machine's HWID using Windows API
std::string get_machine_hwid() {
    HW_PROFILE_INFO hwProfileInfo;
    GetCurrentHwProfile(&hwProfileInfo);

    // Convert wide char to regular char
    char hwid[39];
    wcstombs(hwid, hwProfileInfo.szHwProfileGuid, sizeof(hwid));

    std::string hwidstr(hwid);

    // Remove curly braces if present
    if (!hwidstr.empty() && hwidstr.front() == '{' && hwidstr.back() == '}') {
        hwidstr = hwidstr.substr(1, hwidstr.length() - 2);
    }

    return hwidstr;
}

void debugger_monitor_thread(echoauth::EchoAuthClient*) {
    while (true) {
        if (echoauth::Security::is_debugged()) {
            if (g_authenticated && !g_username.empty() && !g_hwid.empty()) {
                EchoAuth::Log("Debugger detected during background monitoring for user: " + g_username, "critical");
                EchoAuth::Ban(g_username, g_hwid, "Debugger attached during execution");
            }

            std::cerr << "[-] SECURITY VIOLATION: Debugger detected!\n";
            exit(1);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
//main function for the loader, handles authentication, version checking, cheat download, and execution
int main() {
    try {
		// Phase 2: Initial check for analysis environment (VMs, obvious analysis tools)
        if (ProcessMonitor::SuspiciousProcessDetector::detect_virtual_machine()) {
            std::cerr << "[-] SECURITY VIOLATION: Virtual machine detected!\n";
            return 1;
        }

		// Start continuous background process monitoring (5-second intervals, optimized for low CPU)
        ProcessMonitor::BackgroundMonitor::start_monitoring();

		// Initialize EchoAuth client with decrypted config values
        echoauth::EchoAuthClient client(Config::get_api_url(), Config::get_api_secret(), Config::VERIFY_SSL);
        EchoAuth::g_client = &client;

		// Start debugger monitoring thread (immediate detection)
        std::thread debug_monitor(debugger_monitor_thread, &client);
        debug_monitor.detach();

		// Check loader version
        if (!EchoAuth::CheckVersion(Config::LOADER_ID, Config::LOADER_VERSION, get_executable_filename())) {
            std::cerr << "[-] Loader is out of date or invalid filename.\n";
            return 1;
        }


		// Prompt user for credentials using SecureString to protect sensitive data in memory
        StringEncryption::SecureString username, password;
        {
            std::string temp_username, temp_password;
            std::cout << "Username: ";
            std::getline(std::cin, temp_username);
            std::cout << "Password: ";
            std::getline(std::cin, temp_password);
            username = StringEncryption::SecureString(temp_username);
            password = StringEncryption::SecureString(temp_password);
        }

        g_hwid = get_machine_hwid();

		// Perform login with username, password, and HWID
        auto login_resp = EchoAuth::Login(username.c_str(), password.c_str(), g_hwid);

		// Check if login was successful, if not, print error message and exit
        if (!login_resp.success) {
            std::cerr << "[-] Authentication failed: " << login_resp.message << "\n";
            return 1;
        }

        g_username = username.c_str();
        g_authenticated = true;
        EchoAuth::Log("User logged in: " + std::string(username.c_str()), "info");


		// Check for debugger after authentication
        if (EchoAuth::IsDebugger()) {
            std::cerr << "[-] Debugger detected. Your account has been banned.\n";
            EchoAuth::Log("Debugger detected during loader execution for user: " + std::string(username.c_str()), "critical");
            EchoAuth::Ban(username.c_str(), g_hwid, "Debugger detected during loader execution");
            return 1;
        }

		// Verify loader hash integrity (Phase 3)
        std::string hash_info = client.get_loader_hash_info(Config::LOADER_ID);

        std::string current_hash = client.calculate_current_hash();

        if (!EchoAuth::VerifyLoaderHash(Config::LOADER_ID)) {
            std::cerr << "[-] Loader integrity verification failed. This executable may have been tampered with.\n";
            EchoAuth::Ban(username.c_str(), g_hwid, "Loader integrity verification failed");
            return 1;
        }

		// Check if the process is running with elevated privileges (admin rights)
        if (!EchoAuth::IsElevated()) {
            std::cerr << "[-] Process is not running with elevated privileges. Please run as administrator.\n";
            return 1;
        }

		// Download and decrypt cheat module
        auto download_resp = EchoAuth::DownloadCheat(Config::CHEAT_ID, Config::get_xor_key());

        if (!download_resp.success) {
            std::cerr << "[-] Download failed: " << download_resp.message << "\n";
            EchoAuth::Log("Download failed for user: " + g_username, "error");
            return 1;
        }

        EchoAuth::Log("File downloaded successfully by user: " + g_username + " cheat_id: " + std::to_string(Config::CHEAT_ID) + " (size: " + std::to_string(download_resp.file_data.size()) + " bytes)", "info");

		// Check if cheat is detected and prompt user
        if (download_resp.cheat_status == "Detected") {
            std::cerr << "[!] Cheat marked as detected. Continue? (Y/N): ";
            std::string response;
            std::getline(std::cin, response);

            if (response.empty() || (response[0] != 'Y' && response[0] != 'y')) {
                std::cerr << "[-] Execution cancelled.\n";
                return 0;
            }
        }

		// Validate PE header
        if (download_resp.file_data.size() >= 2) {
            unsigned char b1 = (unsigned char)download_resp.file_data[0];
            unsigned char b2 = (unsigned char)download_resp.file_data[1];
        }
        if (!EchoAuth::ValidatePEHeader(download_resp.file_data)) {
            std::cerr << "[-] Invalid PE module\n";
            return 1;
        }

		// Execute the cheat module directly from memory without writing to disk
        EchoAuth::ExecuteFromMemory(download_resp.file_data, "");

        // Clear sensitive data from memory after execution
        EchoAuth::SecureClear(download_resp.file_data);
        std::cerr << "[+] Loader execution complete\n";

        return 0;

	}
	catch (const echoauth::Exception& e) {
        std::cerr << "[-] EchoAuth Error: " << e.what() << "\n";
        return 1;
	}
	catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << "\n";
        return 1;
    }
}
