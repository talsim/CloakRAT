#include <iostream>
#include "TCPClient.h"

int main()
{
	TCPClient* conn = new TCPClient("127.0.0.1", 54000);
	conn->start_connection();
	conn->send_data("hi there");

}
