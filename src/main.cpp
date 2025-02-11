#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <string>
#include <ctime>
#include <fstream>
#include <curl/curl.h>
#include <csignal>
#include <set>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

#define COLOR_RESET  "\033[0m"
#define COLOR_RED    "\033[31m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE   "\033[34m"

void LogMessage(const std::string& message, const std::string& color = COLOR_BLUE);
bool ResetDNSServers();

volatile sig_atomic_t g_running = 1;

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT || 
        signal == CTRL_BREAK_EVENT || signal == CTRL_LOGOFF_EVENT || 
        signal == CTRL_SHUTDOWN_EVENT) {
        LogMessage("Received shutdown signal. Resetting DNS...", COLOR_YELLOW);
        ResetDNSServers();
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}

void LogMessage(const std::string& message, const std::string& color) {
    time_t now = time(0);
    char timestamp[26];
    ctime_s(timestamp, sizeof(timestamp), &now);
    timestamp[24] = '\0';
    std::cout << color << "[" << timestamp << "] " << message << COLOR_RESET << std::endl;
}

bool ExecutePowerShell(const std::wstring& command) {
    std::wstring fullCommand = L"powershell.exe -Command \"& { " + command + L" } | Out-String\"";
    
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        LogMessage("Failed to create pipe: " + std::to_string(GetLastError()), COLOR_RED);
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessW(NULL, (LPWSTR)fullCommand.c_str(), NULL, NULL, TRUE, 
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        LogMessage("Failed to create PowerShell process: " + std::to_string(GetLastError()), COLOR_RED);
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return false;
    }
    
    CloseHandle(hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    std::string output;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
    
    return exitCode == 0;
}

bool VerifyDNSSettings(const std::string& expectedDns) {
    std::wstring verifyCmd = L"$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }; "
                            L"$dnsServers = $adapters | Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses; "
                            L"$dnsServers -contains '" + std::wstring(expectedDns.begin(), expectedDns.end()) + L"'";
    
    return ExecutePowerShell(verifyCmd);
}

bool SetDNSServers(const std::vector<std::string>& dnsServers) {
    std::string dnsString;
    for (const auto& dns : dnsServers) {
        if (!dnsString.empty()) dnsString += ",";
        dnsString += dns;
    }
    
    std::wstring wDnsString(dnsString.begin(), dnsString.end());
    
    std::wstring setDnsCmd = L"$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -like '*Wi-Fi*' -or $_.InterfaceDescription -like '*Ethernet*') }; "
                            L"foreach ($adapter in $adapters) { "
                            L"    Write-Output ('Setting DNS for adapter: ' + $adapter.Name); "
                            L"    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses '" + 
                            wDnsString + L"' -ErrorAction SilentlyContinue; "
                            L"    Write-Output ('Current DNS servers: ' + ((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses -join ', ')); "
                            L"}";
    
    bool success = ExecutePowerShell(setDnsCmd);
    
    Sleep(2000);
    
    return VerifyDNSSettings(dnsServers[0]);
}

bool FlushDNSCache() {
    std::wstring flushCmd = L"ipconfig /flushdns";
    return ExecutePowerShell(flushCmd);
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    return size * nmemb;
}

bool CheckAPI(long& responseCode) {
    CURL *curl;
    CURLcode res;
    bool success = false;
    long http_code = 0;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.krxclient.xyz:443/v1/version/krx-ultimate");
        
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        
        // Set headers
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
        headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
        headers = curl_slist_append(headers, "Cache-Control: no-cache");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);
        
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            responseCode = http_code;
            success = (http_code == 200);
        } else {
            responseCode = 0;
        }

        // Clean up
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return success;
}

bool ResetDNSServers() {
    std::wstring command = L"$adapters = Get-NetAdapter; "
                          L"foreach ($adapter in $adapters) { "
                          L"    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses; "
                          L"}";
    
    return ExecutePowerShell(command);
}

int main() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE)) {
        LogMessage("WARNING: Could not set control handler", COLOR_YELLOW);
    }

    LogMessage("----------------------------------------", COLOR_BLUE);
    LogMessage("KRX DNS Checker", COLOR_BLUE);
    LogMessage("Author: scar17off", COLOR_GREEN);
    LogMessage("GitHub: https://github.com/scar17off/KRXDNSChecker", COLOR_GREEN);
    LogMessage("----------------------------------------", COLOR_BLUE);

    std::vector<std::string> dnsServers;
    std::ifstream dnsFile("dns_servers.txt");
    
    if (!dnsFile.is_open()) {
        LogMessage("ERROR: Could not open dns_servers.txt", COLOR_RED);
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::string line;
    while (std::getline(dnsFile, line)) {
        if (line.empty() || line[0] == '#') continue;
        dnsServers.push_back(line);
    }
    dnsFile.close();

    if (dnsServers.empty()) {
        LogMessage("ERROR: No DNS servers found in dns_servers.txt", COLOR_RED);
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    LogMessage("STARTING DNS checker...", COLOR_BLUE);

    for (const auto& dns : dnsServers) {
        LogMessage("TESTING DNS server: " + dns, COLOR_YELLOW);
        
        if (SetDNSServers({dns})) {
            LogMessage("SUCCESS: Set DNS server to: " + dns, COLOR_GREEN);
            
            // Flush DNS cache
            if (FlushDNSCache()) {
                LogMessage("SUCCESS: Flushed DNS cache", COLOR_GREEN);
            } else {
                LogMessage("WARNING: Failed to flush DNS cache", COLOR_YELLOW);
            }
            
            Sleep(3000);

            long responseCode;
            bool apiResult = CheckAPI(responseCode);
            if (apiResult) {
                LogMessage("SUCCESS: API check successful (HTTP " + std::to_string(responseCode) + ") with DNS: " + dns, COLOR_GREEN);
            } else {
                if (responseCode == 0) {
                    LogMessage("FAILED: API check failed - Connection error with DNS: " + dns, COLOR_RED);
                } else {
                    LogMessage("FAILED: API check failed (HTTP " + std::to_string(responseCode) + ") with DNS: " + dns, COLOR_RED);
                }
            }
        } else {
            LogMessage("FAILED: Could not set or verify DNS server: " + dns, COLOR_RED);
        }

        LogMessage("----------------------------------------", COLOR_BLUE);
    }

    LogMessage("----------------------------------------", COLOR_BLUE);
    LogMessage("DNS Test Results:", COLOR_BLUE);
    LogMessage("----------------------------------------", COLOR_BLUE);

    std::set<std::string> validDNS;
    std::set<std::string> failedDNS;

    for (const auto& dns : dnsServers) {
        if (SetDNSServers({dns})) {
            // Flush DNS cache
            FlushDNSCache();
            Sleep(3000);

            // Check API
            long responseCode;
            bool apiResult = CheckAPI(responseCode);
            if (apiResult) {
                validDNS.insert(dns);
            } else {
                failedDNS.insert(dns);
            }
        } else {
            failedDNS.insert(dns);
        }
    }

    if (!validDNS.empty()) {
        LogMessage("✓ Working DNS Servers:", COLOR_GREEN);
        for (const auto& dns : validDNS) {
            LogMessage("  ├─ " + dns, COLOR_GREEN);
        }
    }

    if (!failedDNS.empty()) {
        LogMessage("✗ Failed DNS Servers:", COLOR_RED);
        for (const auto& dns : failedDNS) {
            LogMessage("  ├─ " + dns, COLOR_RED);
        }
    }

    LogMessage("----------------------------------------", COLOR_BLUE);
    LogMessage("Total Tested: " + std::to_string(dnsServers.size()), COLOR_BLUE);
    LogMessage("Working: " + std::to_string(validDNS.size()), COLOR_GREEN);
    LogMessage("Failed: " + std::to_string(failedDNS.size()), COLOR_RED);
    LogMessage("----------------------------------------", COLOR_BLUE);

    std::cout << "\nPress Enter to exit...";
    while (g_running && std::cin.get()) {
        break;
    }

    // Make sure DNS is reset even on normal exit
    if (g_running) {
        LogMessage("COMPLETED: Testing completed. Resetting DNS servers to DHCP...", COLOR_YELLOW);
        if (ResetDNSServers()) {
            LogMessage("SUCCESS: Reset DNS servers to DHCP", COLOR_GREEN);
        } else {
            LogMessage("FAILED: Could not reset DNS servers to DHCP", COLOR_RED);
        }
    }

    return 0;
}