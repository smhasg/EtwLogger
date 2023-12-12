#pragma once
#include <string>
#include <Windows.h>
#include <vector>

namespace EtwUtils
{
	bool IsRemoteComputer(const std::string& extractedComputerName);
	bool IsRemoteComputer(const std::wstring& extractedComputerName);
	bool IsSubString(const std::wstring& str, const std::wstring& subStr, bool bCaseInsensitive);
	std::string GetProcessNameById(DWORD processId);
	std::string GetProcessPathFromId(DWORD processId);
	DWORD GetParentPID(DWORD pid);
	bool AddPrivilegeToCurrentProcess(const std::string& privilegeName);
	bool ContainsMultipleStrings(const std::wstring& str, const std::vector<std::wstring>& substrings, bool caseInsensitive);
	bool ContainsMultipleStrings(const std::string& str, const std::vector<std::string>& substrings, bool caseInsensitive);
	std::string wstring_to_utf8(const std::wstring& wstr);
	std::wstring utf8_to_wstring(const std::string& str);
	std::string guid_to_string(const GUID& guid);
	void RemoveNewLines(std::string& str);
	std::vector<std::wstring> split(const std::wstring& s, wchar_t delim);
	bool ContainsNonAscii(const std::string& str);
	bool ContainsNonAscii(const std::wstring& str);
	bool ContainsNonPrintable(const std::string& str);
	std::string getComputerName();
};

