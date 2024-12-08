#include <iostream>
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

char* TCPServer::recv_data(int bytes)
{
	char* buf = new char[bytes];

	int bytesReceived = recv(this->clientSock, buf, bytes, 0);

	if (bytesReceived == SOCKET_ERROR)
		std::cerr << "Error in recv(), Err #" << WSAGetLastError() << std::endl;

	else if (bytesReceived > 0)
		std::cout << "CLIENT> " << std::string(buf, bytesReceived);

	else
		std::cout << "Error! Client disconnected maybe?" << std::endl;
	return buf;

}

void TCPServer::close()
{
	closesocket(this->listeningSock);
	closesocket(this->clientSock);
	WSACleanup();
}