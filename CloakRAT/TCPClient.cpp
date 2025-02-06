#include "TCPClient.h"
#include "junk_codes.h"


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
	int wsResult = resolve_dynamically<WSAStartup_t>("WSAStartup", WS2_32_STR)(ver, &data);
	if (wsResult != 0)
	{
		std::cerr << "Error initializing Winsock, Err #" << wsResult << std::endl;
		return -1;
	}

	small_junk();

	// Create Socket
	this->sock = resolve_dynamically<socket_t>("socket", WS2_32_STR)(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		std::cerr << "Error creating socket, Err #" << resolve_dynamically<WSAGetLastError_t>("WSAGetLastError", WS2_32_STR)() << std::endl;
		return -1;
	}
	
	suspicious_junk_2();

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = resolve_dynamically<htons_t>("htons", WS2_32_STR)(port); // convert to big endian (the network byte order)
	resolve_dynamically<inet_pton_t>("inet_pton", WS2_32_STR)(AF_INET, ipAddr.c_str(), &serverAddr.sin_addr);

	int connectionResult = resolve_dynamically<connect_t>("connect", WS2_32_STR)(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));
	if (connectionResult == SOCKET_ERROR)
	{
		std::cerr << "Error connecting to server, Err #" << resolve_dynamically<WSAGetLastError_t>("WSAGetLastError", WS2_32_STR)() << std::endl;
		return -1;
	}
	return 0;
}

void TCPClient::send_data(std::string data)
{
	int garbage = 0x41;

	// Send length header first
	uint32_t len = (uint32_t)data.length();
	uint32_t dataLenInNetworkOrder = resolve_dynamically<htonl_t>("htonl", WS2_32_STR)(len);

	int sendResult = resolve_dynamically<send_t>("send", WS2_32_STR)(this->sock, reinterpret_cast<const char*>(&dataLenInNetworkOrder), sizeof(dataLenInNetworkOrder), 0);
	if (sendResult == SOCKET_ERROR)
	{
		std::cerr << "Error sending length header, Err #" << resolve_dynamically<WSAGetLastError_t>("WSAGetLastError", WS2_32_STR)() << std::endl;
		return;
	}

	int garbage2 = not_inlined_junk_func_3((int)data.at(0), len, &sendResult) ^ 0x41;
	if ((garbage ^ garbage2) == not_inlined_junk_func_3((int)data.at(0), len, &sendResult)) // Always true
	{
		// Now send the data itself
		sendResult = resolve_dynamically<send_t>("send", WS2_32_STR)(this->sock, data.c_str(), len, 0);
		if (sendResult == SOCKET_ERROR)
		{
			std::cerr << "Error sending data to server, Err #" << resolve_dynamically<WSAGetLastError_t>("WSAGetLastError", WS2_32_STR)() << std::endl;
			return;
		}
	}
}

//char* TCPClient::recv_data(int bytes) {
//	char* buf = new char[bytes];
//
//	int bytesReceived = recv(this->sock, buf, bytes, 0);
//	if (bytesReceived > 0)
//	{
//		std::cout << "SERVER> " << std::string(buf, bytesReceived) << std::endl;
//	}
//	return buf;
//}

std::string TCPClient::recv_data() {
	// Receiving the buffer length header
	uint32_t bufLength = 0;
	resolve_dynamically<recv_t>("recv", WS2_32_STR)(this->sock, reinterpret_cast<char*>(&bufLength), 4, 0);
	bufLength = resolve_dynamically<ntohl_t>("ntohl", WS2_32_STR)(bufLength); // Convert to host byte order

	if (bufLength != 0)
	{
		std::string buf(bufLength, '\0');

		// Receiving the actual buffer sent
		int bytesReceived = resolve_dynamically<recv_t>("recv", WS2_32_STR)(this->sock, &buf[0], bufLength, 0);
		if (bytesReceived == SOCKET_ERROR || bytesReceived != bufLength)
			std::cerr << "Error in recv(), Err #" << resolve_dynamically<WSAGetLastError_t>("WSAGetLastError", WS2_32_STR)() << std::endl;

		return buf;
	}
	return std::string("");
}

void TCPClient::close() {
	resolve_dynamically<closesocket_t>("closesocket", WS2_32_STR)(this->sock);
	resolve_dynamically<WSACleanup_t>("WSACleanup", WS2_32_STR)();
}
