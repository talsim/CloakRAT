#pragma once

#include <windows.h>

typedef BOOL (WINAPI* IsDebuggerPresent_t)();
typedef HANDLE (WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef HANDLE (WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef LPVOID (WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

// function definition continues here...
