#include <string> //uint16_t
#include <netinet/in.h> // sockaddr_in

class ping
{
    public:
        static void start_ping(std::string _host);
    private:
        static int32_t checksum(uint16_t *buf, int32_t len);
        static void send_imcp_echo_packet(int, sockaddr_in6, unsigned short, unsigned short);
        /**
         * listen for reply on one packet
         *
         * e.g. this will be called after every packet we send
         *
         * @param sock
         * @param pingaddr the address to recieve packets from
         * @param id the id attached to all outgoing packets
         */
        static unsigned short listen_for_reply(int sock, sockaddr_in6 pingaddr, unsigned short id);
};
