#pragma once
#include <windows.h>
#include <TlHelp32.h>

typedef decltype(IsDebuggerPresent)* IsDebuggerPresent_t;
typedef decltype(ExitThread)* ExitThread_t;
typedef decltype(OpenProcess)* OpenProcess_t;
typedef decltype(WriteProcessMemory)* WriteProcessMemory_t;
typedef decltype(CreateRemoteThread)* CreateRemoteThread_t;
typedef decltype(VirtualAllocEx)* VirtualAllocEx_t;
typedef decltype(CloseHandle)* CloseHandle_t;
typedef decltype(LoadLibraryA)* LoadLibraryA_t;
typedef decltype(LookupPrivilegeValueA)* LookupPrivilegeValueA_t;
typedef decltype(AdjustTokenPrivileges)* AdjustTokenPrivileges_t;
typedef decltype(OpenProcessToken)* OpenProcessToken_t;
typedef decltype(GetCurrentProcess)* GetCurrentProcess_t;
typedef decltype(Sleep)* Sleep_t;
typedef decltype(GetLastError)* GetLastError_t;
typedef decltype(FormatMessageA)* FormatMessageA_t;
typedef decltype(LocalFree)* LocalFree_t;
typedef decltype(CreateProcessA)* CreateProcessA_t;
typedef decltype(CreatePipe)* CreatePipe_t;
typedef decltype(SetHandleInformation)* SetHandleInformation_t;
typedef decltype(ReadFile)* ReadFile_t;
typedef decltype(GetCurrentThread)* GetCurrentThread_t;

// Note: Due to header conflicts between windows.h and WS2tcpip.h, ws2_32.dll related function signatures are directly declared in the TCPClient.h header.

typedef NTSTATUS (NTAPI* NtSetInformationThread_t)(
	HANDLE					 ThreadHandle,	
	DWORD					 ThreadInformationClass,
	PVOID					 ThreadInformation,
	ULONG					 ThreadInformationLength
);
