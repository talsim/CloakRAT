#include "TCPClient.h"

TCPClient::TCPClient(std::string ipAddr, int port)
{
	this->sock = 0;
	this->ipAddr = ipAddr;
	this->port = port;
}

TCPClient::~TCPClient()
{
	this->close();
}

void TCPClient::start_connection()
{
	// Init Winsock
	WSAData data;
	WORD ver = MAKEWORD(2, 2);
	int wsResult = WSAStartup(ver, &data);
	if (wsResult != 0)
	{
		std::cerr << "Error initializing Winsock, Err #" << wsResult << std::endl;
		return;
	}

	// Create Socket
	this->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		std::cerr << "Error creating socket, Err #" << WSAGetLastError() << std::endl;
		return;
	}

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port); // convert to big endian (the network byte order)
	inet_pton(AF_INET, ipAddr.c_str(), &serverAddr.sin_addr);

	int connectionResult = connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));
	if (connectionResult == SOCKET_ERROR)
	{
		std::cerr << "Error connecting to server, Err #" << WSAGetLastError() << std::endl;
		return;
	}
}

void TCPClient::send_data(const char* data)
{
	int sendResult = send(this->sock, data, (int)strlen(data), 0);
	if (sendResult == SOCKET_ERROR)
	{
		std::cerr << "Error sending data to server, Err #" << WSAGetLastError() << std::endl;
		return;
	}
}

char* TCPClient::recv_data(int bytes) {
	char* buf = new char[bytes];

	int bytesReceived = recv(this->sock, buf, bytes, 0);
	if (bytesReceived > 0)
	{
		std::cout << "SERVER> " << std::string(buf, bytesReceived) << std::endl;
	}
	return buf;
}

char* TCPClient::recv_data() {
	// Receiving the buffer length header
	uint32_t bufLength = 0;
	recv(this->sock, reinterpret_cast<char*>(&bufLength), 4, 0);
	bufLength = ntohl(bufLength); // Convert to host byte order

	// Receiving the actual buffer sent (and adding a null terminator)
	char* buf = new char[bufLength + 1];
	buf[bufLength] = '\0';

	recv(this->sock, buf, bufLength, 0);

	return buf;
}

void TCPClient::close() {
	closesocket(this->sock);
	WSACleanup();
}