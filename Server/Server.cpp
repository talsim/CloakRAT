#include <iostream>
#include "TCPServer.h"

int main()
{
	TCPServer* server = new TCPServer(54000);
	server->start();

	std::cout << "Started Server" << std::endl;

	server->accept_conn();
	while (1)
	{
		server->recv_data(200);
	}

	return 0;
}