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
	void close();
	char* recv_data(int bytes);
	void send_data(const char* data);
	int getListeningPort();

private:
	SOCKET listeningSock;
	SOCKET clientSock;
	int listeningPort;
};