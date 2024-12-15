#include <iostream>
#include <bitset>
#include <string>
#include "TCPServer.h"

TCPServer::TCPServer(int port)
{
	this->listeningSock = 0;
	this->listeningPort = port;
	this->clientSock = 0;
}

TCPServer::~TCPServer()
{
	this->close();
}

void TCPServer::start()
{
	// Init WinSock
	WSADATA wsData;
	WORD ver = MAKEWORD(2, 2);

	int wsResult = WSAStartup(ver, &wsData);
	if (wsResult != 0)
	{
		std::cerr << "Error initializing Winsock, Err #" << wsResult << std::endl;
		return;
	}

	this->listeningSock = socket(AF_INET, SOCK_STREAM, 0);
	if (listeningSock == INVALID_SOCKET)
	{
		std::cerr << "Error creating socket, Err #" << WSAGetLastError() << std::endl;
		return;
	}

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(this->listeningPort);
	serverAddr.sin_addr.S_un.S_addr = INADDR_ANY;

	// Bind & Listen
	int bindResult = bind(this->listeningSock, (sockaddr*)&serverAddr, sizeof(serverAddr));
	if (bindResult == SOCKET_ERROR)
	{
		std::cout << "Error binding the socket, Err #" << WSAGetLastError() << std::endl;
		return;
	}


	int listenResult = listen(listeningSock, SOMAXCONN);
	if (listenResult == SOCKET_ERROR)
	{
		std::cout << "Error listening for connections, Err #" << WSAGetLastError() << std::endl;
		return;
	}
}

void TCPServer::accept_conn()
{
	sockaddr_in clientAddr;
	int clientSize = sizeof(clientAddr);

	this->clientSock = accept(this->listeningSock, (sockaddr*)&clientAddr, &clientSize);
	if (this->clientSock == INVALID_SOCKET)
	{
		std::cerr << "Error: Could not accept a new connection from client, Err #" << WSAGetLastError() << std::endl;
		return;
	}
}

std::string TCPServer::recv_data()
{
	// Receive the length first
	uint32_t bufLength = 0;
	recv(this->clientSock, reinterpret_cast<char*>(&bufLength), sizeof(bufLength), 0);
	bufLength = ntohl(bufLength); // Convert back to host endianness

	if (bufLength != 0)
	{
		std::string buf(bufLength, '\0');

		// Receive the data itself
		int bytesReceived = recv(this->clientSock, &buf[0], bufLength, 0);
		if (bytesReceived == SOCKET_ERROR || bytesReceived != bufLength)
			std::cerr << "Error in recv(), Err #" << WSAGetLastError() << std::endl;

		return buf;
	}
	return std::string("");
}

int TCPServer::send_data(std::string buf)
{
	// Sending the 4 bytes length header (not in ascii representation but in raw bytes)
	uint32_t len = (uint32_t)buf.length();
	uint32_t bufLenInNetworkOrder = htonl(len);

	// Send the length header of the buffer
	int sendResult = send(this->clientSock, reinterpret_cast<const char*>(&bufLenInNetworkOrder), sizeof(bufLenInNetworkOrder), 0);
	if (sendResult == SOCKET_ERROR) {
		std::cerr << "Error sending length header to client, Err #" << WSAGetLastError() << std::endl;
		return -1;
	}

	// Send the actual buffer now
	sendResult = send(this->clientSock, buf.c_str(), len, 0);
	if (sendResult == SOCKET_ERROR)
	{
		std::cerr << "Error sending data to client, Err #" << WSAGetLastError() << std::endl;
		return -1;
	}
	return 0;
}

void TCPServer::close()
{
	closesocket(this->listeningSock);
	closesocket(this->clientSock);
	WSACleanup();
}

int TCPServer::getListeningPort()
{
	return this->listeningPort;
}
