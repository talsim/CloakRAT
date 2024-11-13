#include <iostream>
#include <WS2tcpip.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

void main()
{
	std::string ipAddr = "127.0.0.1";
	int port = 54000;

	// Init Winsock
	WSAData data;
	WORD ver = MAKEWORD(2, 2);
	int wsResult = WSAStartup(ver, &data);
	if (wsResult != 0)
	{
		std::cerr << "Error initializing Winsock, Err #" << wsResult << std::endl;
		return;
	}

	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{

		std::cerr << "Error creating socket, Err #" << WSAGetLastError() << std::endl;
		return;
	}

	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port); // convert to big endian (the network byte order)
	inet_pton(AF_INET, ipAddr.c_str(), &hint.sin_addr);

	int connectionResult = connect(sock, (sockaddr*)&hint, sizeof(hint));

}