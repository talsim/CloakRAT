#pragma once
#include <WS2tcpip.h>
#include <iostream>
#include <string>

typedef decltype(WSAStartup)* WSAStartup_t;
typedef decltype(WSACleanup)* WSACleanup_t;
typedef decltype(WSAGetLastError)* WSAGetLastError_t;
typedef decltype(socket)* socket_t;
typedef decltype(send)* send_t;
typedef decltype(recv)* recv_t;
typedef decltype(ntohl)* ntohl_t;
typedef decltype(connect)* connect_t;
typedef decltype(closesocket)* closesocket_t;
typedef decltype(inet_pton)* inet_pton_t;
typedef decltype(htons)* htons_t;
typedef decltype(htonl)* htonl_t;


class TCPClient
{
public:
	TCPClient(std::string ipAddr, int port);
	~TCPClient();
	int start_connection();
	void send_data(std::string data);
	//char* recv_data(int bytes);
	std::string recv_data();
	void close();

private:
	SOCKET sock;
	std::string ipAddr;
	int port;
};