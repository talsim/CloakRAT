#include <windows.h>

HANDLE GetModuleBaseAddr(const char* moduleName);

FARPROC get_proc_address(HMODULE hModule, const char* procedureName);

FARPROC resolve_func(const char* dllName, const char* funcName);