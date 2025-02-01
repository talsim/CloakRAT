#pragma once

#include <windows.h>

void NTAPI TLSCallback(PVOID dllHandle, DWORD reason, PVOID reserved)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		/* Check for debugging here */
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
}

#ifdef _WIN64 
#pragma comment (linker, "/INCLUDE:_tls_used") // include this symbol 
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback_func = TLSCallback;
#pragma const_seg()
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#pragma data_seg(".CRT$XLF")
extern "C" PIMAGE_TLS_CALLBACK _tls_callback_func = TLSCallback;
#pragma data_seg()
#endif

