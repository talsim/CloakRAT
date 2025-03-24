#pragma once

#include <windows.h>
#include <iostream>
#include "windows_peb_structures.h"
#include "winapi_function_signatures.h"
#include "string_encryption.h"

void* get_loaded_module_base_addr(EncryptedString& moduleName);
FARPROC get_proc_address(HMODULE hModule, EncryptedString& procedureName);

// TODO: Add caching the base addresses
template <typename T>
T resolve_dynamically(EncryptedString &funcName, EncryptedString &dllName = str_kernel32)
{
	// Walk through the PEB to find the module's base address
	HMODULE hModule = reinterpret_cast<HMODULE>(get_loaded_module_base_addr((dllName)));
	if (hModule == NULL) // If the module isn't loaded
	{
		// Explicitly load the module with LoadLibraryA()
		LoadLibraryA_t LoadLibraryPtr = resolve_dynamically<LoadLibraryA_t>(str_LoadLibraryA);
		std::string dllNameDecrypted = string_decrypt(dllName);
		hModule = LoadLibraryPtr(dllNameDecrypted.c_str());
		wipeStr(dllNameDecrypted);
	}
		
	FARPROC procAddr = get_proc_address(hModule, funcName);
#ifdef _DEBUG
	if (procAddr == NULL)
		std::cerr << "Failed to resolve function: " + string_decrypt(funcName) << std::endl;
#endif

	return reinterpret_cast<T>(procAddr);
}
