#include "ping.hpp"
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h> 

#include <netinet/ip_icmp.h> 
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <iostream>
#include <iomanip>
#include <errno.h>
#include <chrono>
#include <thread>

#include <vector>
#include <algorithm>
#include <numeric>


void ping::start_ping(const std::string&  destination, const Parameters& p) {
    int pid = getpid() & 0xFFF;
    if (p.verbose) std::cout << " the pid is " << pid << "\n";
    setuid(getuid());
         
    auto start_time = std::chrono::high_resolution_clock::now();

    Destination d{destination};
    PingResults results{ping_destination(d, p, pid)};

    auto end_time = std::chrono::high_resolution_clock::now();
        
    std::chrono::duration<float, std::milli> eplapsed_time = end_time - start_time;
    std::cout << "\t" << destination << " ping stats \t\n";
    std::cout << results.num_sent << " sent packets, " << results.num_recv << " recieved packets.";
    std::cout << std::setprecision(2) << float(results.num_sent - results.num_recv) / float(results.num_sent) * 100 << "% packet loss.";
    std::cout << "time: " << std::setprecision(2) << std::fixed << eplapsed_time.count() << "ms\n";
    std::cout << "rtt min/avg/max: " << std::setprecision(2) << results.stats.min
        << "/" << std::setprecision(2) << results.stats.avg 
        << "/" << std::setprecision(2) << results.stats.max << " ms\n";
}

ping::PingResults ping::ping_destination(const Destination& destination, const Parameters& p, unsigned short id) {
    int sock = (destination.type == IPV6) ? socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) : socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    if (sock < 0) {
        close(sock);
        throw std::runtime_error("Couldn't initalize socket. Your machine may require you to run as root.\n");
    }

    if (destination.type == IPV6) {
        icmp6_filter filter;
        int socket_result = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, (char*) &filter, sizeof(filter));
        if (socket_result < 0) {
            throw std::runtime_error(std::string("Error number %d occured when trying to manipulate socket filter options\n.", errno ));
        }
        
        socket_result = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *) &(p.ttl), sizeof(p.ttl));
        if (socket_result < 0) { 
            throw std::runtime_error(std::string("Couldnt set hop limit on ipv6. Error number %d", errno));
        }
   } else if (destination.type == IPV4) {
        int sock_result = setsockopt(sock, IPPROTO_IP, IP_TTL, (char *) &p.ttl, sizeof(p.ttl)); // TODO: reinsert filters
        if (sock_result < 0) {
            throw std::runtime_error(std::string("Couldnt set ttl options on socket. Error number %d", errno));
        }
    }

    unsigned short num_recieved = 0;
    unsigned short iterator;
    std::vector<float> rtts;
   
    for (iterator = 0; p.packet_quantity != -1 ? iterator < p.packet_quantity : 0; iterator++) { // if packet_quantity == -1, loop infinitely
        auto send_time = std::chrono::high_resolution_clock::now();
        send_imcp_echo_packet(destination, p, sock, iterator, id);
        num_recieved += listen_for_reply(destination, p, sock, id);
        auto recieve_time = std::chrono::high_resolution_clock::now();
        
        std::chrono::duration<float, std::milli> elapsed_time = recieve_time - send_time;
        if (!p.quiet) std::cout << " time elpased:" << elapsed_time.count() << "ms\n";

        rtts.push_back(elapsed_time.count());
        std::this_thread::sleep_for(std::chrono::milliseconds(p.delay));
    }
    PingResults::rtt_statistics stats {
            *std::min_element(rtts.begin(), rtts.end()),
            *std::max_element(rtts.begin(), rtts.end()),
            float(std::accumulate(rtts.cbegin(), rtts.cend(), 0)) / rtts.size()
        };

    close(sock);
    return PingResults{num_recieved, iterator, stats};
}

void ping::send_imcp_echo_packet(const Destination& d, const Parameters& p, int sock, unsigned short seq, unsigned short id) {
    unsigned int header_size = d.type == IPV6 ? sizeof(icmp6_hdr) : sizeof(icmphdr);
    unsigned int data_size = p.packet_size;
    
    char packet[header_size + data_size];
    memset(packet, 0, sizeof(packet));
    char* packet_ptr = packet;

    if (p.verbose) {
        std::cout << "header size: " << header_size << "\tdata size: " << data_size << "\n";
    }

    memset(packet_ptr + header_size, 'J', data_size);
    if (d.type == IPV6) {
        icmp6_hdr *hdr = (icmp6_hdr *) packet_ptr;
        hdr->icmp6_type = ICMP6_ECHO_REQUEST; // ICMP6 ECHO for out, ICMP6_ECHO_REPLY will come back to us
        hdr->icmp6_code = 0; // code 0 = echo reply/req
        hdr->icmp6_id = htons(id); // htons converts the unsigned integer destinationlong to network bye order
        hdr->icmp6_seq = seq; 
        hdr->icmp6_cksum = 0;//checksum((uint16_t *) pkt, sizeof(packet));
        // when looking in wireshark, checksum is being created automatically???
       // memset(pkt->icmp6_dataun.icmp6_un_data8, p.ttl, sizeof(p.ttl));// = p.ttl;
    } else {
       icmphdr *pkt = (icmphdr *) packet_ptr; // everything inside icmphdr is an int or struct of ints
       pkt->type = ICMP_ECHO; // ICMP ECHO for out, ICMP_ECHO_REPLY will come back to us
       pkt->code = 0; // code 0 = echo reply/req
       pkt->un.echo.id = htons(id); // htons converts the unsigned integer hostlong to network bye order
       pkt->un.echo.sequence = seq;
       pkt->checksum = checksum(pkt, sizeof(packet));
    }


    if(p.verbose) {
        std::cout << "Packet created successfully.\n" << "The data is: " << *(packet_ptr + header_size) << "\n";
    }

    int bytes = sendto(sock, packet_ptr, header_size + data_size , 0 /*flags*/, d.get_sock_addr(), d.type == IPV6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));

    if (bytes < 0) {
       close(sock);
       throw std::runtime_error("[SEND] the sendto command returned a value less than 0.\nWe cannot send to the reciever.\n");
   } else if (bytes != header_size + data_size) {
       close(sock);
       throw std::runtime_error("[SEND] could not write entire packet.\nThere may be an internal size mismatch.\n");
   }
}

unsigned short ping::listen_for_reply(const Destination& d, const Parameters& p, int sock, unsigned short id) {
    while (1) {
        // allegedly, recvfrom automatically trims the ipv6 header 
        unsigned int header_size = d.type == IPV6 ? sizeof(icmp6_hdr) : sizeof(icmphdr);
        unsigned int data_size = p.packet_size;
    
       // char inbuf[header_size + data_size];
        char inbuf[MAX_PACKET_SIZE];
        memset(inbuf, 0, sizeof(inbuf));
            
        int addrlen = d.type == IPV6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        int bytes = recvfrom(sock, &inbuf, sizeof(inbuf), 0 /*flags*/, d.get_sock_addr(), (socklen_t *)&addrlen);

        if (bytes < 0) {
            if (p.verbose) std::cout << "[LISTEN] bytes found: " << bytes << "\n\twe expect a value > 0... continuing\n";
            continue;
        }

            if (bytes < sizeof(inbuf)){ 
                if (p.verbose) std::cout << "[LISTEN] Incorrect read bytes! For type " << d.type << "\n\t... continuing\n";
            }

            if (d.type == IPV6) {
                ip6_hdr *iph = (ip6_hdr *)inbuf;  // headerlength is automtically cropped out?????????? 
                icmp6_hdr *pkt = (icmp6_hdr *)(iph); // at this point, inbuf + hlen points to the icmp header
                int extracted_id = ntohs(pkt->icmp6_id); // converts unsigned int from network to destination byte order (opposite of the htons we did earlier! ish)

                if (p.verbose) std::cout << "packet id: " << extracted_id << "\nexpected id: " << id << "\npacket checksum: " << pkt->icmp6_cksum << "\n";
                if (p.verbose) std::cout << "packet type: " << pkt->icmp6_type << "\n";

                if (pkt->icmp6_type == ICMP6_ECHO_REPLY) {
                    if (p.verbose) std::cout << "[LISTEN] packet type of ICMP6 Echo Reply found.\n";

                    if (!p.quiet) {
                        std::cout << header_size + data_size << " bytes from " << d.readable_address << ": icmp_seq=" << pkt->icmp6_seq;
                    }

                    return (extracted_id == id);
                } else if (pkt->icmp6_type == ICMP6_DST_UNREACH) {
                    if (p.verbose) std::cout << "[LISTEN] packet type of ICMP6_DEST_UNREACH\n";

                    int offset = sizeof(ip6_hdr) + sizeof(icmp6_hdr) + sizeof(ip6_hdr); // ip6_hdr + icmp hdr going out + another ip6_hdr coming back in? TODO
                    if (((bytes) - offset) == sizeof(icmp6_hdr))
                    {
                        icmp6_hdr *packet = reinterpret_cast<icmp6_hdr *>(inbuf + offset); // extract the original icmp packet
                        if (ntohs(packet->icmp6_id) == id) {
                            if (p.verbose) std::cout << "\tID's match, destination is unreachable\n";
                            return 0;
                        }
                    }
                } else if (p.verbose) {
                    std::cout << "[LISTEN] Packet found was not an echo reply or DEST_UNREACH, it was: " << pkt->icmp6_type << "\n";
                }
            }  else if (d.type == IPV4) {
                iphdr *iph = (iphdr *)inbuf;
                int hlen = (iph->ihl << 2); // shift left 2
                bytes -= hlen; // subtract the ip header from the bytes, we only care about the icmp info
                icmphdr *pkt = (icmphdr *)(inbuf + hlen); // at this point, inbuf + hlen points to the icmp header
                int extracted_id = ntohs(pkt->un.echo.id); // converts unsigned int from network to host byte order (opposite of the htons we did earlier! ish)

                if (pkt->type == ICMP_ECHOREPLY) {
                    if (p.verbose) std::cout << "[LISTEN] packet type of ICMP Echo Rely found.\n";
                    if (p.verbose) std::cout << "packet id: " << extracted_id << "\nexpected id: " << id << "\npacket checksum: " << pkt->checksum << "\n";

                    if (!p.quiet) {
                        std::cout << sizeof(inbuf) << " bytes from " << d.readable_address << ": icmp_seq=" << pkt->un.echo.sequence << "\n";
                    }
                    return (extracted_id == id);
                }                
                else if (pkt->type == ICMP_DEST_UNREACH) {
                    std::cout << "[LISTEN] packet type of ICMP_DEST_UNREACH\n";

                    int offset = sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr); // iphdr + icmp hdr going out + another iphdr coming back in? TODO
                    if (((bytes + hlen) - offset) == sizeof(icmphdr))
                    {
                        icmphdr *p = reinterpret_cast<icmphdr *>(inbuf + offset); // extract the original icmp packet
                        if (ntohs(p->un.echo.id) == id) {
                            std::cout << "\tID's match, destination is unreachable\n";
                            return 0;
                        }
                    }
                } else if (p.verbose) {
                    std::cout << "[LISTEN] Packet found was not an echo reply or DEST_UNREACH, it was: " << pkt->type << "\n";
            }
        }
    }
    // begin waiting for time out TODO
}

uint16_t ping::checksum(const void* data, size_t len) {
    auto icmph = reinterpret_cast<const uint16_t*>(data);
	uint16_t ret = 0;
	uint32_t sum = 0;
	uint16_t odd_byte;

    len = len % 2 == 0 ? len : len + 1; // checksum only works for even numbers
	while (len > 1) {
		sum += *icmph++;
		len -= 2;
	}

	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
		sum += odd_byte;
	}

	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret =  ~sum;

	return ret;
}
