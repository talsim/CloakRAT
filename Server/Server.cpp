#include <iostream>
#include "TCPServer.h"
#include <string>

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
		server->send_data(commandLine.c_str());
	}

	return 0;
}