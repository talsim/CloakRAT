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
	void start_connection();
	void send_data(const char* data);
	char* recv_data(int bytes);
	int exec(const char* command);
	void close();

private:
	SOCKET sock;
	std::string ipAddr;
	int port;
};