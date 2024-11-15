#pragma once
#include <WS2tcpip.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ws2_32.lib")

class TCPClient
{
public:
	TCPClient(std::string ipAddr, int port);
	~TCPClient();
	std::string ipAddr;
	int port;
	

private:

};