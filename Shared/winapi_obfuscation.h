#pragma once

#include <windows.h>
#include <iostream>
#include "windows_peb_structures.h"
#include "winapi_function_signatures.h"

#define KERNEL32_STR "kernel32.dll"
#define ADVAPI32_STR "advapi32.dll"

void* get_loaded_module_base_addr(const char* moduleName);
FARPROC get_proc_address(HMODULE hModule, const char* procedureName);

// TODO: Add caching the base addresses
template <typename T>
T resolve_dynamically(const char* funcName, const char* dllName = KERNEL32_STR)
{
	// Walk through the PEB to find the module's base address
	HMODULE hModule = reinterpret_cast<HMODULE>(get_loaded_module_base_addr((dllName)));
	if (hModule == NULL) // If the module isn't loaded
	{
		// Explicitly load the module with LoadLibraryA()
		hModule = resolve_dynamically<LoadLibraryA_t>("LoadLibraryA")(dllName);
	}
		
	FARPROC procAddr = get_proc_address(hModule, funcName);
	if (procAddr == NULL)
		std::cerr << "Failed to resolve function: " + std::string(funcName) << std::endl;

	return reinterpret_cast<T>(procAddr);
}
