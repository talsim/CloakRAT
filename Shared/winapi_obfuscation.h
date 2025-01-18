#pragma once

#include <windows.h>
#include <iostream>
#include "windows_peb_structures.h"


#define WKERNEL32_STR L"kernel32.dll"

void* get_loaded_module_base_addr(const wchar_t* moduleName)
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
		if (_wcsicmp(dllName, moduleName) == 0) // Perfrom a case-insensitive string compare
			return ldr_entry->DllBase;

		// Continue to the next entry in the doubly linked list
		curr_list_entry = curr_list_entry->Flink;
	}

	return NULL;
}

FARPROC get_proc_address(HMODULE hModule, const char* procedureName)
{
	BYTE* base_addr = (BYTE*)hModule;
	// How to find the Image Export Directory:
	// Image NT Headers (a pointer to this NT headers can be found at offset 0x3C in the DOS header, which is at the start of the PE after the signature)
	// -> Optional Header -> Image Export Directory RVA is found here
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*) base_addr;
	IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*) image_dos_header->e_lfanew; // Pointer to PE header
	IMAGE_OPTIONAL_HEADER image_optional_header = (IMAGE_OPTIONAL_HEADER) image_nt_headers->OptionalHeader;
	IMAGE_EXPORT_DIRECTORY* image_export_directory = (IMAGE_EXPORT_DIRECTORY*) image_optional_header.DataDirectory->VirtualAddress;
	char** name_table = (char **) image_export_directory->AddressOfNames; // Table of Pointers to strings
	

	// Find the Image Export Directory, which contains 3 useful pointers: to the Export Address Table (EAT), to the Export Name Pointer Table and to the Export Address table which holds the actual RVAs
	// Find the ordinal (index) of the entry to the Export Address Table of the function:
	// 1. loop through each entry in the Export Name Pointer Table with
	// the procedureName argument and save the index of the entry in this table
	// 2. use the previous index found at (1.) to find the ordinal at the Export Ordinal Table with: ordinals_table[name_table_index]
	// Get to the Export Address Table 
	// Extract the RVA at the corresponding ordinal in the EAT
	// Add the base address (base_addr) to the RVA from the last step
	// return the procedure adress

	



	return nullptr;

}

template <typename T>
T resolve_func(const char* funcName, const wchar_t* dllName = WKERNEL32_STR)
{
	HMODULE hModule = reinterpret_cast<HMODULE>(get_loaded_module_base_addr((dllName)));
	if (hModule == NULL)
		std::wcerr << L"Failed to get module handle for " + std::wstring(dllName) << std::endl;

	FARPROC procAddr = get_proc_address(hModule, funcName); // TODO: Replace with get_proc_address()
	if (procAddr == NULL)
		std::wcerr << L"Failed to resolve function: " + std::wstring(dllName) << std::endl;

	return reinterpret_cast<T>(procAddr);
}
