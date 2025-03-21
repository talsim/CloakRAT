#pragma once

#include <windows.h>
#include "utils.h"
#include "winapi_obfuscation.h"
#include "junk_codes.h"

// This callback will be called by the Windows Loader as soon as the DLL is fully loaded to the target process (before DllMain() will be called by LoadLibrary()).
void NTAPI TLSCallback(PVOID dllHandle, DWORD reason, PVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
#ifndef _DEBUG
		if (resolve_dynamically<IsDebuggerPresent_t>(str_IsDebuggerPresent)() || isDebuggerAttached())
		{

			// Segfault 
			rsp_corrupt_destruction();

		}
#endif // _DEBUG
	}
}

#ifdef _WIN64 
/* 
* Include the _tls_used symbol (defined in tlssup.c file in MSVC), and is part of the CRT.
* This symbol represents the TLS Directory in the PE.
*/
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func") // Make sure the linker doesn't ignore the TLS callback pointer we provide (i.e because of unreferenced code)

/* XLA and XLZ symbols from tlssup.c

_CRTALLOC(".CRT$XLA") PIMAGE_TLS_CALLBACK __xl_a = 0;

// NULL terminator for TLS callback array.  This symbol, __xl_z, is never
// actually referenced anywhere, but it must remain.  The OS loader code
// walks the TLS callback array until it finds a NULL pointer, so this makes
// sure the array is properly terminated.

_CRTALLOC(".CRT$XLZ") PIMAGE_TLS_CALLBACK __xl_z = 0;

*/

// Inside the TLS directory, there is a pointer to the callbacks array. the address after __xl_a is the first TLS Callback pointer in the array. It continues until the __xl_z symbol.
// The __xl_a symbol is defined in the .CRT segment of the PE. (see above snippet from tlssup.c)
// Therfore, we tell the linker to place the address of the callback after the __xl_a symbol, at &__xl_a + 1 (which is CRT$XLB, because the linker organizes this alphabetically)
#pragma const_seg(".CRT$XLB") // Place at the &__xl_a + 1 address, to be part of the TLS Callback array of pointers.
/*
* Note: we can also choose to place it at e.g .CRT$XLF and it will work fine, because the linker will merge all sections with .CRT$XL that we defined, to create the TLS Callback array.
* i.e if we define a section and set a null terminator there, then the Windows loader will stop at the first null terminator, and treat it as the end of the array (instead of the last section .CRT$XLZ or the symbol __xl_z)
*/
extern "C" const PIMAGE_TLS_CALLBACK tls_callback_func = TLSCallback; // in x86-64, the access rights to the CRT sections are different than in x86.
#pragma const_seg()
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func") // in x86, the the complier prepends an underscore to symbols
#pragma data_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK tls_callback_func = TLSCallback;
#pragma data_seg()
#endif

