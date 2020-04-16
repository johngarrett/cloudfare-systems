#include "Ping.h"


void parse_agrs();
void help_menu();   

int main()
{
    Ping::ping("192.168.1.1");
    /*
    std::string address = "192.168.2.1";
    Ping::ping(address, type=.IPV6, size=64, ...);
    */
    return 0;
}
