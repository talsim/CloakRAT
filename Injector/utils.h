#pragma once

bool SetPrivilege(
	HANDLE hToken,          // Access token handle
	LPCTSTR lpszPrivilege,  // Name of the privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable, FALSE to disable
);

// Enable the SeDebugPrivilege in the access token of the process
// Returns 0 if succeeded, and -1 otherwise.
int EscalatePrivilege();

DWORD GetProcessIdByName(const char* procName);
