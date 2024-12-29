#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

DWORD getProcessIdByName(const char* procName)
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

int main()
{
	const char* dllPath = "FOO";
	const char* procName = "explorer.exe";

	DWORD procID = 0;
	while (!procID) // while the process was not found
	{
		procID = getProcessIdByName(procName);
		Sleep(100);
	}

	HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);

	if (procHandle && procHandle != INVALID_HANDLE_VALUE) // if we got a handle successfully
	{
		LPVOID dllAddrInRemoteProcess = VirtualAllocEx(procHandle, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (dllAddrInRemoteProcess) {
			WriteProcessMemory(procHandle, dllAddrInRemoteProcess, dllPath, strlen(dllPath) + 1, 0);
		}
		else
		{
			std::cout << "Error: VirtualAllocEx() returned NULL: Err #" << GetLastError() << std::endl;
			return 1;
		}
		
		HANDLE threadHandle = CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dllAddrInRemoteProcess, 0, 0);

		CloseHandle(threadHandle);
	}

	return 0;

}