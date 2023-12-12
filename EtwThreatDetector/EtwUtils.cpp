#include "EtwAgent.h"
#include "EtwUtils.h"

#include <Psapi.h>
#include <TlHelp32.h>
#include <cwctype>
#include <codecvt>
#include <locale>
#include <iostream>


namespace EtwUtils
{
    bool IsRemoteComputer(const std::string& extractedComputerName) {
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName) / sizeof(computerName[0]);

        if (extractedComputerName.length() == 0)
            return false;

        if (!GetComputerNameA(computerName, &size)) 
            return false;

        std::string currentComputerName(computerName);
        std::transform(currentComputerName.begin(), currentComputerName.end(), currentComputerName.begin(), ::tolower);
        std::string lowerExtractedComputerName(extractedComputerName);
        std::transform(lowerExtractedComputerName.begin(), lowerExtractedComputerName.end(), lowerExtractedComputerName.begin(), ::tolower);

        DBG_LOG("Current computer : %s - Extracted computer : %s ", currentComputerName.c_str(), lowerExtractedComputerName.c_str() );

        return currentComputerName.find(lowerExtractedComputerName) == std::string::npos;
    }

    bool IsRemoteComputer(const std::wstring& extractedComputerName) {
        wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName) / sizeof(computerName[0]);

        if (extractedComputerName.length() == 0)
            return false;

        if (!GetComputerNameW(computerName, &size))
            return false;

        std::wstring currentComputerName(computerName);
        std::transform(currentComputerName.begin(), currentComputerName.end(), currentComputerName.begin(), ::tolower);
        std::wstring lowerExtractedComputerName(extractedComputerName);
        std::transform(lowerExtractedComputerName.begin(), lowerExtractedComputerName.end(), lowerExtractedComputerName.begin(), ::tolower);

        DBG_LOG("Current computer : %ws - Extracted computer : %ws ", currentComputerName.c_str(), lowerExtractedComputerName.c_str());

        return currentComputerName.find(lowerExtractedComputerName) == std::wstring::npos;
    }


    bool IsSubString(const std::wstring& str, const std::wstring& subStr, bool bCaseInsensitive = false) {
        std::wstring src = str;
        std::wstring target = subStr;

        // Convert strings to lower case for case-insensitive comparison
        if (bCaseInsensitive) {
            std::transform(src.begin(), src.end(), src.begin(), ::towlower);
            std::transform(target.begin(), target.end(), target.begin(), ::towlower);
        }

        // Check if 'target' is a substring of 'src'
        return src.find(target) != std::wstring::npos;
    }


    std::string GetProcessNameById(DWORD processId) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return "";
        }

        if (Process32First(snapshot, &entry)) {
            do {
                if (entry.th32ProcessID == processId) {
                    CloseHandle(snapshot);
                    return entry.szExeFile;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return "";
    }

    std::string GetProcessPathFromId(DWORD processId) {
        CHAR filePath[MAX_PATH] = { 0 };

        if (processId == 0)
            return "";

        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (processHandle) {
            if (!GetModuleFileNameExA(processHandle, nullptr, filePath, MAX_PATH)) {
                CloseHandle(processHandle);
                return GetProcessNameById(processId);
            }
            CloseHandle(processHandle);
        }
        else {
            return GetProcessNameById(processId);
        }

        return filePath;
    }


    DWORD GetParentPID(DWORD pid) {
        HANDLE hSnapshot;
        PROCESSENTRY32 pe32;
        INT ppid = 0;

        // Take a snapshot of all processes in the system
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return static_cast<DWORD>(-1);
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Retrieve information about the first process
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    ppid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return ppid;
    }


    bool AddPrivilegeToCurrentProcess(const std::string& privilegeName) {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }

        // Use a smart pointer for automatic resource management
        std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&CloseHandle)> hTokenSmartPtr(hToken, CloseHandle);

        TOKEN_PRIVILEGES tkp;
        if (!LookupPrivilegeValueA(nullptr, privilegeName.c_str(), &tkp.Privileges[0].Luid)) {
            return false;
        }

        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, nullptr)) {
            return false;
        }

        DWORD lastError = GetLastError();
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
            return false;
        }
        else if (lastError != ERROR_SUCCESS) {
            return false;
        }

        DBG_LOG("Privilege %s added successfully.\n", privilegeName.c_str());
        return true;
    }


    bool ContainsMultipleStrings(const std::wstring& str, const std::vector<std::wstring>& substrings, bool caseInsensitive) {
        for (const auto& subStr : substrings) {
            if (caseInsensitive) {
                auto it = std::search(
                    str.begin(), str.end(),
                    subStr.begin(), subStr.end(),
                    [](wchar_t ch1, wchar_t ch2) { return std::towlower(ch1) == std::towlower(ch2); }
                );

                if (it == str.end()) {
                    return false;
                }
            }
            else {
                if (str.find(subStr) == std::wstring::npos) {
                    return false;
                }
            }
        }

        return true;
    }


    bool ContainsMultipleStrings(const std::string& str, const std::vector<std::string>& substrings, bool caseInsensitive) {
        for (const auto& subStr : substrings) {
            if (caseInsensitive) {
                auto it = std::search(
                    str.begin(), str.end(),
                    subStr.begin(), subStr.end(),
                    [](char ch1, char ch2) { return std::tolower(ch1) == std::tolower(ch2); }
                );

                if (it == str.end()) {
                    return false;
                }
            }
            else {
                if (str.find(subStr) == std::string::npos) {
                    return false;
                }
            }
        }

        return true;
    }


    std::string wstring_to_utf8(const std::wstring& wstr) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.to_bytes(wstr);
    }

    std::wstring utf8_to_wstring(const std::string& str) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.from_bytes(str);
    }


    std::string guid_to_string(const GUID& guid) {
        std::ostringstream stream;
        stream << std::hex << std::setfill('0')
            << std::setw(8) << guid.Data1 << '-'
            << std::setw(4) << static_cast<short>(guid.Data2) << '-'
            << std::setw(4) << static_cast<short>(guid.Data3) << '-'
            << std::setw(2) << static_cast<short>(guid.Data4[0])
            << std::setw(2) << static_cast<short>(guid.Data4[1]) << '-'
            << std::setw(2) << static_cast<short>(guid.Data4[2])
            << std::setw(2) << static_cast<short>(guid.Data4[3])
            << std::setw(2) << static_cast<short>(guid.Data4[4])
            << std::setw(2) << static_cast<short>(guid.Data4[5])
            << std::setw(2) << static_cast<short>(guid.Data4[6])
            << std::setw(2) << static_cast<short>(guid.Data4[7]);
        return stream.str();
    }


    void RemoveNewLines(std::string& str) {
        // Remove \r
        str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());

        // Remove \n
        str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
    }


    // Helper function to split a string by a delimiter and return a vector
    std::vector<std::wstring> split(const std::wstring& s, wchar_t delim) {
        std::vector<std::wstring> elems;
        std::wstringstream ss(s);
        std::wstring item;
        while (std::getline(ss, item, delim)) {
            elems.push_back(item);
        }
        return elems;
    }


    bool DirectoryExists(const std::string& dirName) {
        DWORD ftyp = GetFileAttributesA(dirName.c_str());
        if (ftyp == INVALID_FILE_ATTRIBUTES)
            return false;

        if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
            return true;

        return false;
    }


    void EnsureEtwLogFolderExists() {
        char buffer[MAX_PATH];
        GetModuleFileName(NULL, buffer, MAX_PATH);
        std::string::size_type pos = std::string(buffer).find_last_of("\\/");
        std::string folderPath = std::string(buffer).substr(0, pos) + "\\EtwLogs";

        if (!DirectoryExists(folderPath)) {
            if (CreateDirectory(folderPath.c_str(), NULL)) {
                std::cout << "Folder created: " << folderPath << std::endl;
            }
            else {
                std::cerr << "Failed to create folder: " << folderPath << std::endl;
            }
        }
        else {
            std::cout << "Folder already exists: " << folderPath << std::endl;
        }
    }


    bool ContainsNonAscii(const std::string& str) {
        for (char c : str) {

            if (static_cast<unsigned char>(c) > 127) {
                return true; // Found a non-ASCII character
            }
        }
        return false; // No non-ASCII characters found
    }

    bool ContainsNonAscii(const std::wstring& str) {
        for (wchar_t wc : str) {
            if (static_cast<unsigned long>(wc) > 127) {
                return true; // Found a non-ASCII character
            }
        }
        return false; // No non-ASCII characters found
    }

    bool ContainsNonPrintable(const std::string& str) {
        for (char ch : str) {
            if (!std::isprint(static_cast<unsigned char>(ch))) {
                return true; // Non-printable character found
            }
        }
        return false; // No non-printable characters found
    }


    std::string getComputerName() {
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);

        if (!GetComputerNameA(computerName, &size)) {
            return "";
        }

        return std::string(computerName);
    }

}
