#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "utils.h"

bool SetPrivilege(
	HANDLE hToken,          // Access token handle
	LPCTSTR lpszPrivilege,  // Name of the privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable, FALSE to disable
) {
	TOKEN_PRIVILEGES tp;
	LUID luid;

	// Retrieve the LUID for the specified privilege
	if (!LookupPrivilegeValue(
		NULL,            // Lookup privilege on the local system
		lpszPrivilege,   // Privilege to lookup
		&luid))			 // Receives the LUID of the privilege
	{
		std::cerr << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

	// Enable or disable the privilege in the access token
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL))
	{
		std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
		return false;
	}

	// Check for any errors that may have occurred during the adjustment
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		std::cerr << "The token does not have the specified privilege." << std::endl;
		return false;
	}

	return true;
}

// Enable the SeDebugPrivilege in the access token of the process
int EscalatePrivilege()
{
	HANDLE hToken;

	// Open the access token associated with the current process
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
		return -1;
	}

	// Attempt to enable SeDebugPrivilege
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		std::cerr << "Failed to enable SeDebugPrivilege." << std::endl;
		return -1;
	}

	CloseHandle(hToken);
	return 0;
}


DWORD GetProcessIdByName(const char* procName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, procName) == 0)
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		}
	}

	return 0;
}