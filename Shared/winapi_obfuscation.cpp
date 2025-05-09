#include <windows.h>
#include <iostream>
#include "windows_peb_structures.h"
#include "junk_codes.h"
#include "byte_encryption.h"


static std::wstring to_wstring(const char* narrowStr);
static PPEB GetPEB();

// Walking through the PEB here to find the base addr
void* get_loaded_module_base_addr(EncryptedBytes &moduleName)
{
	PPEB peb = GetPEB();
	PLIST_ENTRY head_list_entry = &peb->Ldr->InLoadOrderModuleList; // When the InLoadOrderModuleList doubly linked list reaches the last entry, it circles to the head of the list (the first entry)
	PLIST_ENTRY curr_list_entry = peb->Ldr->InLoadOrderModuleList.Flink;

	while (curr_list_entry != head_list_entry)
	{
		// Get the start address of the structure LDR_DATA_TABLE_ENTRY from its member InLoadOrderLinks
		PLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(curr_list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		// Check if BaseDllName is the moduleName paramater
		PWSTR dllName = ldr_entry->BaseDllName.Buffer;

		std::string moduleNameDecrypted = decrypt_string(moduleName);
		std::wstring wideModuleName = to_wstring(moduleNameDecrypted.c_str());
		if (_wcsicmp(dllName, wideModuleName.c_str()) == 0) // Perfrom a case-insensitive string compare
			return ldr_entry->DllBase;

		// Wipe the decrypted module name string
		wipeStr(moduleNameDecrypted);
		SecureZeroMemory(&wideModuleName[0], wideModuleName.size());
		wideModuleName.clear();

		// Continue to the next entry in the doubly linked list
		curr_list_entry = curr_list_entry->Flink;
	}

	return NULL;
}

FARPROC get_proc_address(HMODULE hModule, EncryptedBytes &procedureName)
{
	// How to find the Image Export Directory:
	// Image NT Headers (a offset to the NT headers can be found at offset 0x3C in the DOS header, which is at the start of the PE after the signature)
	// -> Optional Header -> Image Export Directory RVA is found here
	// Find the Image Export Directory, which contains 3 useful pointers: to the Export Address Table (EAT), to the Export Name Pointer Table and to the Export Address table which holds the actual RVAs
	// Find the ordinal (index) of the entry to the Export Address Table of the function:
	// 1. loop through each entry in the Export Name Pointers Table with
	// the procedureName argument and save the index of the entry in this table
	// 2. use the previous index found at (1.) to find the ordinal at the Export Ordinal Table with: ordinals_table[name_table_index]
	// Extract the RVA at the corresponding ordinal in the EAT
	// Add the base address (base_addr) to the RVA from the last step
	// return the procedure adress

	BYTE* base_address = (BYTE*)hModule;
	FARPROC address = nullptr;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)base_address;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(base_address + dos_header->e_lfanew); // Offset to the PE/NT header
	IMAGE_OPTIONAL_HEADER optional_header = nt_headers->OptionalHeader;
	IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)(base_address + optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // RVA to the export directory

	DWORD* name_table = (DWORD*)(base_address + export_directory->AddressOfNames); // Table of Export Name Pointers (points to strings)
	DWORD* address_table = (DWORD*)(base_address + export_directory->AddressOfFunctions); // Export Address Table (points to function addresses)
	WORD* ordinal_table = (WORD*)(base_address + export_directory->AddressOfNameOrdinals); // Export Ordinal Table

	std::string procedureNameDecrypted = decrypt_string(procedureName);
	for (DWORD i = 0; i < export_directory->NumberOfNames; i++)
	{
		char* name = (char*)(base_address + name_table[i]); // Dereference to a string 

		if (_stricmp(procedureNameDecrypted.c_str(), name) == 0) // Perfrom a case-insensitive string compare between the procedure names
		{
			address = (FARPROC)(base_address + (DWORD)address_table[ordinal_table[i]]); // base_address + the RVA of the procedure
			wipeStr(procedureNameDecrypted);
			break;
		}
	}

	return address;
}

static std::wstring to_wstring(const char* narrowStr)
{
	size_t len = strlen(narrowStr) + 1;
	std::wstring wideStr(len, L'\0');
	mbstowcs_s(nullptr, &wideStr[0], len, narrowStr, len - 1); // Convert string
	wideStr.resize(len - 1); // Trim trailing null character
	
	return wideStr;
}

static PPEB GetPEB() {
#ifdef _WIN64
	return (PPEB)__readgsqword(0x60);
#else
	return (PPEB)__readfsdword(0x30);
#endif 
}