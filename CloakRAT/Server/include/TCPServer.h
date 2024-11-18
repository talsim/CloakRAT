#pragma once
#include <iostream>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")


class TCPServer
{
public:
	TCPServer(int port);
	~TCPServer();
	void start(); // binds and listens
	void accept_conn();

private:
	SOCKET listeningSock;
	SOCKET clientSock;
	int listeningPort;
};