#pragma once

#include <windows.h>
#include <TlHelp32.h>

//typedef BOOL (WINAPI* IsDebuggerPresent_t)();
//typedef HANDLE (WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
//typedef BOOL (WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
//typedef HANDLE (WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
//typedef LPVOID (WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef decltype(IsDebuggerPresent)* IsDebuggerPresent_t;
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
