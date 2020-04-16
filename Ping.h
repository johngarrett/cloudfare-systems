#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <iostream>


class Ping {
    enum ADD_TYPE { IPV4, IPV6 };
    public:
        static void ping(const std::string& address)
        {
            struct sockaddr_in to, from;
            std::cout << address << "\n";

            to.sin_family = AF_INET;
            to.sin_addr.s_addr = inet_addr(address.c_str());

            
        }

    private:
        unsigned int checksum();
        void validate_address();
        void listen_for_response();
        void decode_packet()
        {
            /*
             * ICMP response codes are defined in ip_icmp
             * https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip_icmp.h.html
             */
        }
        void send_packet();
        void init_icmp_header(ADD_TYPE type)
        {
            if (type == IPV4) 
            {
                icp->icmp_type = ICMP_ECHO;
                icp->icmp_code = 0; // echo request
                icp->icmp_cksum = 0;
                icp->icmp_seq = 12345;
                icp->icmp_id = 420;
            }
        }
};
