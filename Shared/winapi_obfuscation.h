#pragma once

#include <windows.h>

HANDLE GetLoadedModuleBaseAddr(const char* moduleName)
{
	// Walking through the PEB here to find the base addr
	return nullptr;
}

FARPROC get_proc_address(HMODULE hModule, const char* procedureName)
{
	// Manual impl of GetProcAddress()
	return nullptr;
}

template <typename T>
T resolve_func(const char* funcName, const char* dllName = "kernel32.dll")
{
	HMODULE hModule = GetModuleHandleA(dllName); // TODO: Replace with GetLoadedModuleBaseAddr()
	if (hModule == NULL)
		throw std::runtime_error("Failed to get module handle for " + std::string(dllName));

	FARPROC procAddr = GetProcAddress(hModule, funcName); // TODO: Replace with get_proc_address()
	if (procAddr == NULL)
		throw std::runtime_error("Failed to resolve function: " + std::string(funcName));

	return reinterpret_cast<T>(procAddr);
}
