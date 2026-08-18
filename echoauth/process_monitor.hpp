#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <thread>
#include <windows.h>
#include <tlhelp32.h>

namespace ProcessMonitor {
    class SuspiciousProcessDetector {
    private:
        // List of known debuggers and analysis tools
        static constexpr const char* SUSPICIOUS_PROCESSES[] = {
            "ollydbg.exe",
            "windbg.exe",
            "x64dbg.exe",
            "x32dbg.exe",
            "ida.exe",
            "ida64.exe",
            "radare2.exe",
            "ghidra.exe",
            "wireshark.exe",
            "fiddler.exe",
            "burp.exe",
            "cheatengine.exe",
            "process_monitor.exe",
            "procmon.exe",
            "regmon.exe",
            "filemon.exe",
            "tcpview.exe",
            "apispy.exe",
            "decompiler.exe",
            "dotpeek.exe",
            "dnspy.exe",
            "ilspy.exe",
            "reflector.exe",
            "themida.exe",
            "vmware.exe",
            "virtualbox.exe",
            "vbox.exe",
            "qemu.exe",
            "hyperv.exe",
            "xen.exe"
        };

    public:
        // Get list of running processes
        static std::vector<std::string> get_running_processes() {
            std::vector<std::string> processes;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (snapshot == INVALID_HANDLE_VALUE) {
                return processes;
            }

            PROCESSENTRY32 entry;
            entry.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(snapshot, &entry)) {
                do {
                    char buffer[MAX_PATH];
                    WideCharToMultiByte(CP_ACP, 0, entry.szExeFile, -1, buffer, MAX_PATH, NULL, NULL);
                    processes.push_back(std::string(buffer));
                } while (Process32Next(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return processes;
        }

        // Convert string to lowercase for comparison
        static std::string to_lower(const std::string& str) {
            std::string result = str;
            for (char& c : result) {
                c = tolower(c);
            }
            return result;
        }

        // Check if any suspicious processes are running
        static bool detect_suspicious_processes() {
            std::vector<std::string> processes = get_running_processes();

            for (const auto& process : processes) {
                std::string lower_process = to_lower(process);

                for (const auto& suspicious : SUSPICIOUS_PROCESSES) {
                    if (lower_process.find(suspicious) != std::string::npos) {
                        return true; // Suspicious process found
                    }
                }
            }

            return false; // No suspicious processes found
        }

        // Get list of detected suspicious processes
        static std::vector<std::string> get_detected_processes() {
            std::vector<std::string> detected;
            std::vector<std::string> processes = get_running_processes();

            for (const auto& process : processes) {
                std::string lower_process = to_lower(process);

                for (const auto& suspicious : SUSPICIOUS_PROCESSES) {
                    if (lower_process.find(suspicious) != std::string::npos) {
                        detected.push_back(process);
                        break;
                    }
                }
            }

            return detected;
        }

        // Check for common analysis VM fingerprints
        static bool detect_virtual_machine() {
            // Check for VMware
            if (GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVirtualDiskHandle") != NULL) {
                return true;
            }

            // Check for VirtualBox
            HANDLE device = CreateFileA("\\\\.\\VBoxMiniRdrDN", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (device != INVALID_HANDLE_VALUE) {
                CloseHandle(device);
                return true;
            }

            // Check registry keys
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }

            return false;
        }

        // Comprehensive security check
        static bool is_analysis_environment() {
            return detect_suspicious_processes() || detect_virtual_machine();
        }
    };

    // Background monitoring thread - runs efficiently in the background
    class BackgroundMonitor {
    public:
        static const int CHECK_INTERVAL_MS = 5000; // Check every 5 seconds

        static void start_monitoring() {
            std::thread monitor_thread([]() {
                while (true) {
                    try {
                        // Only check for suspicious processes (VM check only at startup)
                        if (SuspiciousProcessDetector::detect_suspicious_processes()) {
                            exit(1); // Immediately terminate if threat detected
                        }
                    } catch (...) {
                        // Silently ignore errors to avoid noise
                    }

                    // Sleep for 5 seconds before next check - optimized for low CPU
                    Sleep(CHECK_INTERVAL_MS);
                }
            });
            monitor_thread.detach();
        }
    };
}
