#include <arpa/inet.h>
#include <netinet/in.h>  // sockaddr_in
#include <netdb.h>  // getaddrinfo

#include <string>  // uint16_t
#include <stdexcept>
#include <iomanip>
#include <ostream>
#include<cstring>
#include <chrono>

#ifndef PING_H
#define PING_H
class Ping {
    #define MAX_PACKET_SIZE 65506

 public:
        struct Parameters {
            bool make_sound = false;
            bool quiet = false;
            bool verbose = false;
            bool show_timestamps = true;
            int packet_quantity = -1;  // -1 yeilds a loop until a termination command is sent
            unsigned int packet_size = 64;
            int rtt = 255;
            unsigned short delay = 500;
        };
        struct PingResults {
            struct rtt_statistics {
                float min;
                float max;
                float avg;
            };
            unsigned short num_recv;
            unsigned short num_sent;
            float elapsed_time;

            PingResults::rtt_statistics stats;
            std::string to_string() {
                std::stringstream ostream;
                ostream << num_sent << " sent packets, " << num_recv << " recieved packets."
                    << std::setprecision(2) << (static_cast<float>(num_sent - num_recv))/num_sent * 100 << "% packet loss."
                    << "time: " << std::setprecision(2) << std::fixed << elapsed_time << "ms\n"
                    << "rtt min/avg/max: " << std::setprecision(2) << stats.min
                    << "/" << std::setprecision(2) << stats.avg
                    << "/" << std::setprecision(2) << stats.max << " ms\n";
                return ostream.str();
            }
        };
        static void ping(const std::string& destination);
        static PingResults start_ping(const std::string& destination, const Parameters& p);

 private:
        enum protocol { IPV4, IPV6 };
        struct Destination {
         public:
                std::string readable_address;
                protocol type;

                explicit Destination(std::string address) {
                    readable_address = address;
                    if (inet_pton(AF_INET6, address.c_str(), &addr.sin6_addr) == 1) {
                        type = IPV6;
                        addr.sin6_family = AF_INET6;
                    } else if (inet_pton(AF_INET, address.c_str(), &legacy_addr.sin_addr) == 1) {
                        type = IPV4;
                        legacy_addr.sin_family = AF_INET;
                    } else {
                        try {
                            addrinfo *info;
                            memset(info, 0, sizeof(addrinfo));
                            info->ai_family = IPV6;
                            type = IPV6;
                            addr.sin6_family = AF_INET6;

                            addrinfo hints = { 0 };
                            addrinfo* addr;
                            hints.ai_family = AF_INET6;
                            getaddrinfo(address.c_str(), nullptr, &hints, &addr);
                        } catch (std::exception &e) {
                            throw(std::invalid_argument("The destination was neither an IPV4 address, IPV6 address or valid hostname"));
                        }
                    }
                }

                sockaddr* get_sock_addr() const {
                    // could not use c++ casting here
                    return (type == IPV6 ? (sockaddr *)&addr : (sockaddr *)&legacy_addr);
                }

         private:
            struct sockaddr_in legacy_addr;
            struct sockaddr_in6 addr;
        };
        /* compute the icmp4 checksum for a pointer with length len */
        static uint16_t checksum(const void* data, size_t len);
        /* ping the destination d with parameters p and an id for the packet */
        static PingResults ping_destination(const Destination& d, const Parameters& p, unsigned short id);
        /* send an echo packet to the destination d with parameters p through socket sock, with an id and sequence number */
        static void send_imcp_echo_packet(const Destination& d, const Parameters& p, int sock, unsigned short id, unsigned short seq);
        /* listen for a reply from destination d, with params p, through the socket sock. send over the start time to cacluate rtt as well 
         * returns 1 if there was an echo reply, 0 if not
         */
        static unsigned short listen_for_reply(const Destination& d, const Parameters& p, int sock, unsigned short id, const std::chrono::high_resolution_clock::time_point&);
};
#endif
