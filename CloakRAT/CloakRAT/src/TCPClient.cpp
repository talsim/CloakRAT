#include "TCPClient.h"

TCPClient::TCPClient(std::string ipAddr, int port)
{
	this->ipAddr = ipAddr;
	this->port = port;
}

TCPClient::~TCPClient() {}

int main()
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
		return 1;
	}

	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{

		std::cerr << "Error creating socket, Err #" << WSAGetLastError() << std::endl;
		return 1;
	}

	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port); // convert to big endian (the network byte order)
	inet_pton(AF_INET, ipAddr.c_str(), &hint.sin_addr);

	int connectionResult = connect(sock, (sockaddr*)&hint, sizeof(hint));
	if (connectionResult == SOCKET_ERROR)
	{
		std::cerr << "Error connecting to server, Err #" << WSAGetLastError() << std::endl;
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	char buf[4096] = "";
	std::string userInput = "";

	do {
		std::cout << "> ";
		std::getline(std::cin, userInput);
		unsigned int len = userInput.length();

		if (len > 0)
		{
			// Send the input to the server
			int sendResult = send(sock, userInput.c_str(), len + 1, 0);
			if (sendResult != SOCKET_ERROR)
			{
				memset(buf, 0, sizeof(buf));
				int bytesReceived = recv(sock, buf, sizeof(buf), 0);
				if (bytesReceived > 0)
				{
					std::cout << "SERVER> " << std::string(buf, bytesReceived);
				}
			}
		}

	} while (userInput.length() > 0);

	closesocket(sock);
	WSACleanup();

	return 0;
}