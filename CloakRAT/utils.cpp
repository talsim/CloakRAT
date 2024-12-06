#include <windows.h>
#include <iostream>
#include <string>

namespace {
	void createChildProc(HANDLE stdOutRead, HANDLE stdOutWrite, char* commandLine)
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
		if (!CreateProcessA(NULL, (char*)commandLine, NULL, NULL, true, CREATE_NO_WINDOW, NULL, NULL, &startInfo, &procInfo)) {
			std::cerr << "Error: CreateProcessA() failed, Err #" << GetLastError() << std::endl;
			return;
		}
		else {
			CloseHandle(procInfo.hProcess);
			CloseHandle(procInfo.hThread);
			CloseHandle(stdOutWrite);
		}
	}
}

char* exec(char* commandLine)
{
	SECURITY_ATTRIBUTES securityAttr;

	HANDLE stdOutWrite = nullptr;
	HANDLE stdOutRead = nullptr;

	memset(&securityAttr, 0, sizeof(securityAttr));
	securityAttr.nLength = sizeof(securityAttr);
	securityAttr.bInheritHandle = true;
	securityAttr.lpSecurityDescriptor = NULL;

	// Create an STDOUT Pipe for the child process
	if (!CreatePipe(&stdOutRead, &stdOutWrite, &securityAttr, 0)) {
		std::cerr << "Error: CreatePipe() failed, Err #" << GetLastError() << std::endl;
		return nullptr;
	}

	if (!SetHandleInformation(stdOutRead, HANDLE_FLAG_INHERIT, 0)) {
		std::cerr << "Error: SetHandleInformation() failed, Err #" << GetLastError()<< std::endl;
		return nullptr;
	}


	// Create the child process
	createChildProc(stdOutRead, stdOutWrite, commandLine);

	// Read from the child process STDOUT Pipe
	// Return the result from STDOUT
}

