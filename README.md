# EchoAuth Loader

A reference implementation and production-ready loader for the EchoAuth authentication system. Demonstrates secure cheat module download, execution, and session management with comprehensive security features.

## Features

- ✅ **Version Checking** - Validates loader is up-to-date before authentication
- ✅ **User Authentication** - Secure login with username/password
- ✅ **HWID Locking** - Session bound to specific hardware
- ✅ **Debugger Detection** - Continuous monitoring, auto-ban on detection
- ✅ **Filename Validation** - Ensures running official executable
- ✅ **Cheat Download** - Secure XOR-encrypted module delivery
- ✅ **Status Checking** - Prompts user if cheat marked as detected
- ✅ **PE Validation** - Verifies downloaded file is valid PE format
- ✅ **In-Memory Execution** - Executes cheat without disk writes
- ✅ **Secure Cleanup** - Clears sensitive data after use
- ✅ **Error Handling** - Comprehensive error messages and logging
- ✅ **API Logging** - Submits execution logs to backend

## Building

### Requirements

- **Visual Studio 2022** or later
- **Windows SDK** (for Windows headers)
- **C++17** or later
- **EchoAuth Library** (libEchoAuthLib.lib)

### Build Steps

1. Open `EchoAuthLoader.sln` in Visual Studio
2. Configure:
   - Configuration: **Release** (recommended)
   - Platform: **x64** (recommended) or **Win32**
3. Build → Build Solution (Ctrl+Shift+B)
4. Output: `build/Release/EchoAuthLoader.exe`

### Linking Dependencies

The loader requires:
- `EchoAuthLib.lib` or `EchoAuthClient.lib`
- System libraries: `wininet.lib advapi32.lib crypt32.lib`

## Configuration

Edit `main.cpp` to configure for your setup:

```cpp
namespace Config {
    const char* API_URL = "http://localhost:3001";           // Backend URL
    const char* API_SECRET = "your-api-secret-key";          // API secret
    const char* XOR_KEY = "your-xor-encryption-key";         // Cheat XOR key
    const int CHEAT_ID = 2;                                  // Cheat ID to download
    const int LOADER_ID = 1;                                 // Loader ID
    const char* LOADER_VERSION = "1.0.0";                    // Current version
    const char* LOADER_FILENAME = "EchoAuthLoader.exe";      // Expected filename
    const bool VERIFY_SSL = true;                            // Verify SSL (true for prod)
}
```

## Running

```bash
EchoAuthLoader.exe
```

**Interactive Flow:**
1. Checks loader version (exits if out of date)
2. Prompts for username and password
3. Retrieves HWID and authenticates
4. Monitors for debugger (banned if detected)
5. Downloads encrypted cheat module
6. Prompts if cheat marked as detected
7. Validates PE header
8. Executes module in memory
9. Clears sensitive data
10. Exits

## Workflow

### 1. Version Check

```
[*] Checking loader version...
```

- Sends loader ID and current version to backend
- Validates filename matches (if enabled)
- Exits if update available

### 2. Authentication

```
Username: user123
Password: ****
```

- Retrieves machine HWID using `GetCurrentHwProfile()`
- Sends login request with HWID
- Server binds session to HWID
- Stores token for API requests

### 3. Debugger Detection

```
[-] SECURITY VIOLATION: Debugger detected!
```

- Background thread checks every 100ms
- If debugger detected, immediately bans user
- No chance for attacker to bypass security

### 4. Cheat Download

```
[+] Login successful
```

- Requests cheat file with XOR encryption key
- Server returns encrypted binary
- Validates cheat status (Detected/Undetected)

### 5. Status Prompt

```
[!] Cheat marked as detected. Continue? (Y/N):
```

- If cheat marked as detected, asks user
- User can choose to cancel or proceed
- Useful for informing users of risk

### 6. Execution

```
[+] Module executed successfully
```

- Decrypts XOR-encrypted cheat file
- Validates PE header (MZ signature)
- Executes from memory (no disk writes)
- Securely clears all sensitive data

## Security Features

### Debugger Detection

- Continuous background monitoring (100ms interval)
- Uses Windows `IsDebuggerPresent()` and `CheckRemoteDebuggerPresent()`
- Immediately exits and bans user if detected
- Prevents reverse engineering and tampering

### Filename Validation

- Ensures loader running with correct executable name
- Can be optional per cheat configuration
- Prevents renamed/modified loaders
- Server configurable per cheat

### HWID Locking

- Session bound to specific hardware ID
- Retrieved via `GetCurrentHwProfile()`
- Prevents account sharing across machines
- Validated on authentication

### PE Validation

- Checks PE header (MZ signature) before execution
- Ensures downloaded file is valid Windows PE
- Prevents corrupt or malicious file execution

### Memory Security

- Cheat executed from memory only (no temp files)
- Sensitive data cleared with `SecureZeroMemory()`
- Prevents disk forensics recovery
- Clears passwords, tokens, and decrypted modules

### API Logging

- Submits execution logs to backend
- Tracks successful/failed executions
- Logs security events (debugger detection, bans)
- Useful for monitoring and debugging

## Error Handling

Common errors and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| Version check failed | Backend unreachable | Check API_URL and network |
| Loader is out of date | Version mismatch | Download latest version |
| Invalid loader filename | Filename doesn't match | Rename or verify config |
| Authentication failed | Wrong credentials | Check username/password |
| Debugger detected | Debugger running | Close debugger and retry |
| Download failed | Cheat not found | Check CHEAT_ID and permissions |
| Invalid PE module | Corrupt/wrong file | Verify XOR_KEY and CHEAT_ID |
| Execution failed | Module error | Check cheat status |

## API Endpoints Used

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/client/loader/check-version` | Check loader version |
| POST | `/api/auth/login` | Authenticate user |
| POST | `/api/client/download` | Download cheat file |
| POST | `/api/client/ban` | Ban user for security violation |
| POST | `/api/client/submit-log` | Log execution event |

## Code Structure

```cpp
main.cpp
├── Config namespace
│   ├── API_URL
│   ├── API_SECRET
│   ├── XOR_KEY
│   └── Other settings
├── Global state
│   ├── g_authenticated
│   ├── g_username
│   └── g_hwid
├── Utility functions
│   ├── get_executable_filename()
│   └── get_machine_hwid()
├── Debugger monitor
│   └── debugger_monitor_thread()
└── Main function
    ├── Version check
    ├── Authentication
    ├── Debugger check
    ├── Download
    ├── Execute
    └── Cleanup
```

## Performance

- **Startup**: ~500ms (network check + auth)
- **Version check**: ~200ms
- **Authentication**: ~300-500ms
- **Download**: 1-10MB depending on cheat size
- **Decryption**: 10-50ms for typical files
- **Execution**: Module dependent
- **Memory overhead**: ~2-5MB base + module size

## Best Practices

### For Developers

1. **Change default config** - Update API_URL, API_SECRET, XOR_KEY
2. **Use HTTPS in production** - Set VERIFY_SSL to true
3. **Update version regularly** - Increment LOADER_VERSION
4. **Test on clean machine** - Verify HWID locking works
5. **Monitor logs** - Check backend for execution logs

### For Cheat Creators

1. **Don't disable debugger check** - Critical security feature
2. **Encrypt cheat modules** - Use XOR or stronger encryption
3. **Validate PE header** - Ensures module integrity
4. **Clear sensitive data** - Use SecureZeroMemory()
5. **Respect rate limits** - Implement user-side throttling
6. **Update frequently** - Keep users on latest version

## Troubleshooting

### Loader Crashes on Startup

```
[-] Error: Cannot load library
```

- Verify EchoAuthLib.lib is linked
- Check system libraries are linked
- Ensure headers are in include path

### Version Check Fails

```
[-] Version check failed: [network error]
```

- Check API_URL is correct
- Verify backend is running
- Check firewall/network settings

### Authentication Fails

```
[-] Authentication failed: Invalid credentials
```

- Verify username and password
- Check user exists on backend
- Verify HWID is not banned

### Debugger Detection Issues

```
[-] SECURITY VIOLATION: Debugger detected!
```

- Close all debuggers (IDE, WinDbg, etc.)
- Disable breakpoints
- Don't attach debugger after launch
- Test on clean machine

### Module Execution Fails

```
[-] Invalid PE module
```

- Verify XOR_KEY is correct
- Check CHEAT_ID points to valid file
- Ensure cheat file hasn't been corrupted
- Verify backend has cheat uploaded

## Security Considerations

### Development

- Use `VERIFY_SSL = false` only for local testing
- Never commit credentials to repository
- Use strong API secrets (32+ characters)
- Test on isolated/VM environment

### Production

- Set `VERIFY_SSL = true` for HTTPS
- Use strong, unique API secrets
- Distribute only signed/verified executables
- Monitor for suspicious login patterns
- Update cheat status when detected
- Ban compromised accounts immediately

## Advanced Configuration

### Custom Cheat Download

To support multiple cheats:

```cpp
std::cout << "Available cheats:\n";
std::cout << "1. Cheat A\n";
std::cout << "2. Cheat B\n";
std::cout << "Select: ";
int choice;
std::cin >> choice;

int cheat_id = (choice == 1) ? 1 : 2;
auto download = client.download_cheat(cheat_id, Config::XOR_KEY);
```

### Custom Execution Method

The loader uses in-memory execution. To customize:

```cpp
echoauth::MemoryExecutor::execute_from_memory(decrypted, "target_process");
```

See memory.hpp for advanced execution methods.

## License

Proprietary - EchoAuth

---

For complete API documentation and guides, see:
- C++ Library: [cpp/Lib/README.md](../Lib/README.md)
- Frontend docs: http://localhost:3000/documentation/cpp-library
- API Reference: http://localhost:3000/documentation/api-reference
