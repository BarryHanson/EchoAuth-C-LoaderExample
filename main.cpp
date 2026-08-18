#define _CRT_SECURE_NO_WARNINGS

#include "echoauth/client.hpp"
#include "echoauth/crypto.hpp"
#include "echoauth/exceptions.hpp"
#include "security.hpp"
#include "memory.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <windows.h>


//Replace these values with your own from the EchoAuth dashboard
namespace Config {
	const char* API_URL = "http://62.72.7.120:3001"; //replace with your EchoAuth API URL (currently localhost for testing)
	const char* API_SECRET = "secret_a7544bad113a54f9dfcbe9729929b3091f70597003dd7b70e6e065d3c8148310"; //get it from your dashboard -> settings -> api
    const char* XOR_KEY = "secure_xor_key_12345";
    const int CHEAT_ID = 2;
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

//thread function to monitor for debugger attachment(Thank you chatgpt)
void debugger_monitor_thread(echoauth::EchoAuthClient* client) {
    while (true) {
        if (echoauth::Security::is_debugged()) {
            if (g_authenticated && !g_username.empty() && !g_hwid.empty()) {
                try {
                    std::string ban_body = "{\"username\":\"" + g_username + "\",\"hwid\":\"" + g_hwid + "\",\"reason\":\"Debugger attached during execution\"}";
                    client->http_post("/api/client/ban", ban_body);

                    std::string log_body = "{\"message\":\"Debugger detected during execution\",\"level\":\"critical\"}";
                    client->http_post("/api/client/submit-log", log_body);
                } catch (...) {}
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
		// Initialize EchoAuth client
        echoauth::EchoAuthClient client(Config::API_URL, Config::API_SECRET, Config::VERIFY_SSL);

		// Start debugger monitoring thread
        std::thread debug_monitor(debugger_monitor_thread, &client);
        debug_monitor.detach();

        std::cerr << "[*] Checking loader version...\n";

		// Perform version check with the EchoAuth API
        try {
            std::string actual_filename = get_executable_filename();
            std::string version_body = "{\"loaderId\":" + std::to_string(Config::LOADER_ID) +
                                     ",\"currentVersion\":\"" + Config::LOADER_VERSION +
                                     "\",\"filename\":\"" + actual_filename + "\"}";
            std::string version_response = client.http_post("/api/client/loader/check-version", version_body);

			// Check if the response indicates the loader is out of date or has an invalid filename
            if (version_response.find("\"isUpToDate\":false") != std::string::npos) {
                std::cerr << "[-] Loader is out of date. Current: " << Config::LOADER_VERSION << "\n";
                std::cerr << "[-] Please download the latest version.\n";
                std::cerr << "\n[*] Press Enter to exit...\n";
                std::cin.get();
                return 1;
            }

			// Check if the response indicates the loader filename does not match the expected filename
            if (version_response.find("\"filenameMatch\":false") != std::string::npos) {
                std::cerr << "[-] Invalid loader filename. Expected: " << Config::LOADER_FILENAME <<
                         ", Got: " << actual_filename << "\n";
                std::cerr << "[-] Please use the official loader executable.\n";
                std::cerr << "\n[*] Press Enter to exit...\n";
                std::cin.get();
                return 1;
            }

            std::cerr << "[+] Version check passed\n";
        } catch (const std::exception& e) {
            std::cerr << "[-] Version check failed: " << e.what() << "\n";
        }


		// Prompt user for credentials
        std::string username, password;
        std::cerr << "Username: ";
        std::getline(std::cin, username);
        std::cerr << "Password: ";
        std::getline(std::cin, password);

        g_hwid = get_machine_hwid();

		// Perform login with username, password, and HWID
        echoauth::LoginResponse login_resp = client.login(username, password, g_hwid);

		//Check if login was successful, if not, print error message and exit
        if (!login_resp.success) {
            std::cerr << "[-] Authentication failed: " << login_resp.message << "\n";
            return 1;
        }

        g_username = username;
        g_authenticated = true;
        std::cerr << "[+] Login successful\n";


		// Check for debugger after authentication
        if (echoauth::Security::is_debugged()) {
            std::cerr << "[-] Debugger detected. Your account has been banned.\n";
            std::string ban_body = "{\"username\":\"" + username + "\",\"hwid\":\"" + g_hwid +
                                  "\",\"reason\":\"Debugger detected during loader execution\"}";
            client.http_post("/api/client/ban", ban_body);
            return 1;
        }

		// Check if the process is running with elevated privileges (admin rights)
        if (!echoauth::Security::is_elevated()) {
            std::cerr << "[-] Process is not running with elevated privileges. Please run as administrator.\n";
            return 1;
        }

		// Download the cheat module from the EchoAuth API
        echoauth::CheatFileDownloadResponse download_resp = client.download_cheat(Config::CHEAT_ID, Config::XOR_KEY);

        if (!download_resp.success) {
            std::cerr << "[-] Download failed: " << download_resp.message << "\n";
            return 1;
        }

		// Check if the cheat is marked as detected via the EchoAuth API and prompt the user for confirmation
        if (download_resp.cheat_status == "Detected") {
            std::cerr << "\n[!] Cheat marked as detected. Continue? (Y/N): ";
            std::string response;

            std::getline(std::cin, response);

            if (response.empty() || (response[0] != 'Y' && response[0] != 'y')) {
                std::cerr << "[-] Execution cancelled.\n";
                return 0;
            }
        }

		// Decrypt the downloaded cheat module using XOR decryption
        auto decrypted = echoauth::Crypto::xor_encrypt(download_resp.file_data, Config::XOR_KEY);

		// Validate the decrypted PE module to ensure it is a valid executable
        if (!echoauth::MemoryExecutor::validate_pe_header(decrypted)) {
            std::cerr << "[-] Invalid PE module\n";
            return 1;
        }

		// Execute the decrypted cheat module directly from memory without writing to disk
        echoauth::MemoryExecutor::execute_from_memory(decrypted, "");

        // Clear sensitive data from memory after execution
        echoauth::Security::secure_clear(download_resp.file_data);
        echoauth::Security::secure_clear(decrypted);

        return 0;

	}
	catch (const echoauth::Exception& e) { // Catch EchoAuth-specific exceptions
        std::cerr << "[-] EchoAuth Error: " << e.what() << "\n";
        std::cerr << "\n[*] Press Enter to exit...\n";
        std::cin.get();
        return 1;
	}
	catch (const std::exception& e) { //  Catch standard exceptions
        std::cerr << "[-] Error: " << e.what() << "\n";
        std::cerr << "\n[*] Press Enter to exit...\n";
        std::cin.get();
        return 1;
    }
}
