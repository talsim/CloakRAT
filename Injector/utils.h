#pragma once

#include "byte_encryption.h"

bool SetPrivilege(
	HANDLE hToken,          // Access token handle
	LPCTSTR lpszPrivilege,  // Name of the privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable, FALSE to disable
);

// Enable the SeDebugPrivilege in the access token of the process
// Returns 0 if succeeded, and -1 otherwise.
int EscalatePrivilege();

DWORD GetProcessIdByName(EncryptedBytes& procName);
