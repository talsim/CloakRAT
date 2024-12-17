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
	// TODO
	const char* dllPath = "";
	const char* procName = "";

	DWORD procID = 0;
	while (!procID) // while the process was not found
	{
		procID = getProcessIdByName(procName);
		Sleep(100);
	}

	HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);
	
	if (procHandle && procHandle != INVALID_HANDLE_VALUE) // if we got a handle successfuly
	{
		void* addr = VirtualAllocEx(procHandle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		// WriteProcessMemory()
		// CreateRemoteThread(..., LoadLibrary())
	}

	return 0;

}