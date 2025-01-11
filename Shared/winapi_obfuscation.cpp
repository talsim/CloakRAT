#include <windows.h>
#include <iostream>
#include "winapi_obfuscation.h"

HANDLE GetModuleBaseAddr(const char* moduleName)
{
	// Walking through the PEB here to find the base addr
	return nullptr;
}

FARPROC get_proc_address(HMODULE hModule, const char* procedureName)
{
	// Manual impl of GetProcAddress()
	return nullptr;
}

FARPROC resolve_func(const char* dllName, const char* funcName)
{
	HMODULE hModule = GetModuleHandleA(dllName); // TODO: Replace with GetModuleBaseAddr()
	if (hModule == NULL)
		throw std::runtime_error("Failed to get module handle for " + std::string(dllName));

	FARPROC funcAddr = GetProcAddress(hModule, funcName); // TODO: Replace with get_proc_address()
	if (funcAddr == NULL)
		throw std::runtime_error("Failed to resolve function: " + std::string(funcName));

	return funcAddr;
}