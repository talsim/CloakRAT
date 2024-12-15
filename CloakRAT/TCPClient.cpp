#include "TCPClient.h"
#include <string>

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

int TCPClient::start_connection()
{
	// Init Winsock
	WSAData data;
	WORD ver = MAKEWORD(2, 2);
	int wsResult = WSAStartup(ver, &data);
	if (wsResult != 0)
	{
		std::cerr << "Error initializing Winsock, Err #" << wsResult << std::endl;
		return -1;
	}

	// Create Socket
	this->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		std::cerr << "Error creating socket, Err #" << WSAGetLastError() << std::endl;
		return -1;
	}

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port); // convert to big endian (the network byte order)
	inet_pton(AF_INET, ipAddr.c_str(), &serverAddr.sin_addr);

	int connectionResult = connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));
	if (connectionResult == SOCKET_ERROR)
	{
		std::cerr << "Error connecting to server, Err #" << WSAGetLastError() << std::endl;
		return -1;
	}
	return 0;
}

void TCPClient::send_data(std::string data)
{
	// Send length header first
	uint32_t len = (uint32_t)data.length();
	uint32_t dataLenInNetworkOrder = htonl(len);

	int sendResult = send(this->sock, reinterpret_cast<const char*>(&dataLenInNetworkOrder), sizeof(dataLenInNetworkOrder), 0);
	if (sendResult == SOCKET_ERROR)
	{
		std::cerr << "Error sending length header, Err #" << WSAGetLastError() << std::endl;
		return;
	}

	// Now send the data itself
	sendResult = send(this->sock, data.c_str(), len, 0);
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

std::string TCPClient::recv_data() {
	// Receiving the buffer length header
	uint32_t bufLength = 0;
	recv(this->sock, reinterpret_cast<char*>(&bufLength), 4, 0);
	bufLength = ntohl(bufLength); // Convert to host byte order

	if (bufLength != 0)
	{
		std::string buf(bufLength, '\0');

		// Receiving the actual buffer sent
		int bytesReceived = recv(this->sock, &buf[0], bufLength, 0);
		if (bytesReceived == SOCKET_ERROR || bytesReceived != bufLength)
			std::cerr << "Error in recv(), Err #" << WSAGetLastError() << std::endl;

		return buf;
	}
	return std::string("");
}

void TCPClient::close() {
	closesocket(this->sock);
	WSACleanup();
}