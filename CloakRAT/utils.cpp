#include <windows.h>
#include <iostream>
#include <string>

namespace {
	// On success returns 0, otherwise -1.
	int createChildProc(HANDLE stdOutRead, HANDLE stdOutWrite, const char* commandLine)
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
			return -1;
		}

		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);
		CloseHandle(stdOutWrite);
		return 0;
	}
}

std::string exec(const char* commandLine)
{
	// TODO: CONSTRUCT THE COMMAND LINE! CURRENTLY IT IS JUST PLAIN FROM THE USER, E.g entering "notepad++" opens notepad++.exe lol (so it kinda works hahah)
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
		return "";
	}

	if (!SetHandleInformation(stdOutRead, HANDLE_FLAG_INHERIT, 0)) {
		std::cerr << "Error: SetHandleInformation() failed, Err #" << GetLastError() << std::endl;
		return "";
	}

	// Create the child process
	int createChildProcResult = createChildProc(stdOutRead, stdOutWrite, commandLine);
	if (createChildProcResult == -1)
		return "";

	// Read from the child process STDOUT Pipe
	DWORD bytesRead = 0;
	char buf[4096];
	std::string commandResult = "";

	memset(buf, 0, sizeof(buf));
	while (ReadFile(stdOutRead, buf, sizeof(buf), &bytesRead, NULL) && bytesRead != 0) // while there are still bytes to read
		commandResult.append(buf, bytesRead);

	CloseHandle(stdOutRead);

	// Return the result from STDOUT
	return commandResult;
}

