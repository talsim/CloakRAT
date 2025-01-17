#pragma once

#include <windows.h>
#include "windows_peb_structures.h"


void* GetLoadedModuleBaseAddr(const wchar_t* moduleName)
{
	// Walking through the PEB here to find the base addr
	PPEB peb = GetPEB();
	PLIST_ENTRY head_list_entry = &peb->Ldr->InLoadOrderModuleList; // When the InLoadOrderModuleList doubly linked list reaches the last entry, it circles to the head of the list
	PLIST_ENTRY curr_list_entry = peb->Ldr->InLoadOrderModuleList.Flink;
	
	while (curr_list_entry != head_list_entry)
	{
		// Get the start address of the structure LDR_DATA_TABLE_ENTRY from its member InLoadOrderLinks
		PLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(curr_list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		// Check if BaseDllName is the moduleName paramater
		PWSTR dllName = ldr_entry->BaseDllName.Buffer;
		if (_wcsicmp(dllName, moduleName) == 0) // if the dll is kernel32
			return ldr_entry->DllBase;

		// Continue to the next entry in the doubly linked list
		curr_list_entry = curr_list_entry->Flink;
	}
	
	return NULL;
}

FARPROC get_proc_address(HMODULE hModule, const char* procedureName)
{
	// Manual impl of GetProcAddress()
	return NULL;
}

template <typename T>
T resolve_func(const char* funcName, const wchar_t* dllName = L"kernel32.dll")
{
	HMODULE hModule = reinterpret_cast<HMODULE>(GetLoadedModuleBaseAddr((dllName))); // TODO: Replace with GetLoadedModuleBaseAddr()
	if (hModule == NULL)
		throw std::runtime_error("Failed to get module handle for ");

	FARPROC procAddr = GetProcAddress(hModule, funcName); // TODO: Replace with get_proc_address()
	if (procAddr == NULL)
		throw std::runtime_error("Failed to resolve function: ");

	return reinterpret_cast<T>(procAddr);
}
