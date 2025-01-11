#pragma once

#include <windows.h>

typedef BOOL(WINAPI* IsDebuggerPresent_t)();
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);

// function definition continues here...
