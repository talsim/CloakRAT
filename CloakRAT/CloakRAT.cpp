#include <iostream>
#include "TCPClient.h"
#include "utils.h"

int main()
{
	TCPClient* conn = new TCPClient("127.0.0.1", 54000);
	conn->start_connection();
	conn->send_data("Hello World!");
	while (true)
	{
		std::string userInput = "";
		std::getline(std::cin, userInput);
		std::string result = exec(userInput.c_str());
		std::cout << result << std::endl;
	}
	return 0;
}
