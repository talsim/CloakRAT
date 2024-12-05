#include <windows.h>
#include <iostream>
#include <string>

char* exec(const char* command)
{
	SECURITY_ATTRIBUTES securityAttr;
	HANDLE stdOutWrite = nullptr;
	HANDLE stdOutRead = nullptr;

	memset(&securityAttr, 0, sizeof(securityAttr));
	securityAttr.nLength = sizeof(securityAttr);
	securityAttr.bInheritHandle = true;
	securityAttr.lpSecurityDescriptor = NULL;

	// Create an STDOUT Pipe for the child process
	// Create the child process
	// Read from the child process STDOUT Pipe
	// Return the result from STDOUT
}