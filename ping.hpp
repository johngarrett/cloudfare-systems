#include <string> //uint16_t
#include <stdexcept>
#include <arpa/inet.h>
#include <netinet/in.h> // sockaddr_in


class ping
{
    #define MAX_PACKET_SIZE 65506 
    public:
        struct Parameters {
            bool make_sound = false;
            bool quiet = false;
            bool verbose = false;
            bool show_timestamps = true;
            int packet_quantity = -1;
            unsigned int packet_size = 64; 
            int ttl = 255;
            unsigned short delay = 500;
        };
        static void start_ping(const std::string& destination, const Parameters& p);
    private:
        enum protocol { IPV4, IPV6 };
        struct Destination {
            public:
                std::string readable_address;
                protocol type;
                Destination(std::string address) {
                    readable_address = address;
                    if (inet_pton(AF_INET6, address.c_str(), &addr.sin6_addr) == 1) { 
                        type = IPV6;
                        addr.sin6_family = AF_INET6;
                    } else if (inet_pton(AF_INET, address.c_str(), &legacy_addr.sin_addr) == 1) {
                        type = IPV4;
                        legacy_addr.sin_family = AF_INET;
                    } else {
                        throw std::invalid_argument("Destination is neither a valid IPv4 or IPv6 address");  
                    }
                }
                sockaddr* get_sock_addr() const {
                    return (type == IPV6 ? (sockaddr *)&addr : (sockaddr *)&legacy_addr);
                }

            private:
                struct sockaddr_in legacy_addr;
                struct sockaddr_in6 addr;
        };

        struct PingResults {
            struct rtt_statistics {
                float min;
                float max;
                float avg;
            };
            unsigned short num_recv;
            unsigned short num_sent;
            PingResults::rtt_statistics stats;
        };

        static int32_t checksum(const Destination& d, const Parameters& p);
        static void generateICMPHeader(char* buffer, int packet_size, int id, int seq, protocol type);
        static PingResults ping_destination(const Destination& d, const Parameters& p, unsigned short id);
        static void send_imcp_echo_packet(const Destination& d, const Parameters& p, int sock, unsigned short, unsigned short);
        /**
         * listen for reply on one packet
         *
         * e.g. this will be called after every packet we send
         *
         * @param sock
         * @param pingaddr the address to recieve packets from
         * @param id the id attached to all outgoing packets
         */
        static unsigned short listen_for_reply(const Destination& d, const Parameters& p, int sock, unsigned short id);
        static uint16_t checksum(const void* data, size_t len);
};
