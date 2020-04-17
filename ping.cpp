#include "ping.h"
#include <arpa/inet.h>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/ip_icmp.h> 
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/in.h> // sockaddr_in

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <stdint.h>
#include <cstring> // string arrays
#include <unistd.h> // for closing sockets
#include <errno.h>

void ping::start_ping(std::string dest) {
    /*
     * strange error:
     * pid > 5 numbers breaks
     * temp solution
     */
    int pid = getpid(); // this is the id for the header

    while (pid/ 100000 != 0) pid /= 10;
    std::cout << " the pid is " << pid << "\n";
    /*
     * each packet needs a UID, that way we can retrive the right on when listening for echo backs
     *  - using process ID for this TODO: check that
     *      - wrong, this de-esclates the root program so the pid is accessable by the user
     */
    setuid(getuid());
         
    struct sockaddr_in6 destination;
    struct sockaddr_in legacy_destination;

    if (inet_pton(AF_INET6, dest.c_str(), &destination.sin6_addr) == 1)
        ping_destination(destination, pid);
    else if (inet_pton(AF_INET, dest.c_str(), &legacy_destination.sin_addr) == 1)
        ping_destination(legacy_destination, pid);
    else
        throw std::invalid_argument("Destination is neither a valid IPv4 or IPv6 address");  
}

void ping::ping_destination(sockaddr_in6 destination, unsigned short id) {
    destination.sin6_family = AF_INET6;

    int sock = socket(AF_INET6, // domain
                     SOCK_RAW, // type (we are circumventing TCP or UDP)
                     IPPROTO_ICMPV6); // protocol (the number that appears in the header (ECHO REPLY/REQ))

    if (sock < 0) { // an error occured
        close(sock);
        throw std::runtime_error("Couldn't initalize socket. Your machine may require you to run as root.\n");
    }

    /**
     * when listening for an echo reply, we only want to listen for an echo reply
     * notes:
     *  - ICMP_SOURCE_QUENCH was depricated in IPv6
     */
    icmp6_filter filter;
    // TODO: add filter types, read source
    
    std::cout << sock << "\n";
    // setsockopt is a command to "manipulate socket options" for the socket we just created
    int socket_result = setsockopt(sock, // int representation of our socket
                            IPPROTO_ICMPV6, // the level we are operating on
                            ICMP6_FILTER, // the type for the following option
                            (char *)&filter, // the options we are sending over, filters
                            sizeof(filter));

    if (socket_result < 0) {
        // TODO: throw errno as well
        throw std::runtime_error("An error occured when trying to manipulate socket options\n.");
    }

    unsigned short num_recieved = 0;

    for (int i = 0; i < 5; i++) {
        std::cout << "attempting ping #" << i+1 << "\n";
        send_imcp_echo_packet(sock, destination, i, id);
        num_recieved += listen_for_reply(sock, destination, id);
    }
    std::cout << "we recived " << num_recieved << " packets back";
}
void ping::ping_destination(sockaddr_in destination, unsigned short id) {
    destination.sin_family = AF_INET;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock < 0) { 
        close(sock);
        throw std::runtime_error("Couldn't initalize socket. Your machine may require you to run as root.\n");
    }

    /*
     * icmp_filter filter;
    filter.data = ~((1<<ICMP_SOURCE_QUENCH) |
                    (1<<ICMP_DEST_UNREACH) |
                    (1<<ICMP_TIME_EXCEEDED) |
                    (1<<ICMP_REDIRECT) |
                    (1<<ICMP_ECHOREPLY)); 

    if(setsockopt(sock, SOL_RAW, ICMP_FILTER, (char *)&filter, sizeof(filter)) < 0) {
        throw std::runtime_error("An error occured when trying to manipulate socket options\n.");
    }*/

    unsigned short num_recieved = 0;

    for (int i = 0; i < 5; i++) {
        std::cout << "attempting ping #" << i+1 << "\n";
        send_imcp_echo_packet(sock, destination, i, id);
        num_recieved += listen_for_reply(sock, destination, id);
    }
    std::cout << "we recived " << num_recieved << " packets back";
}

void ping::send_imcp_echo_packet(int sock, sockaddr_in6 pingaddr, unsigned short seq, unsigned short id) {
    char packet[sizeof(icmp6_hdr)];
    memset(packet, 0, sizeof(packet)); // fill with zeros to ensure no corruption or anything
    
    icmp6_hdr *pkt = (icmp6_hdr *)packet; // everything inside icmp6_hdr is an int or struct of ints
    pkt->icmp6_type = ICMP6_ECHO_REQUEST; // ICMP6 ECHO for out, ICMP6_ECHO_REPLY will come back to us
    pkt->icmp6_code = 0; // code 0 = echo reply/req
    pkt->icmp6_id = htons(id & 0xFFFF); // htons converts the unsigned integer destinationlong to network bye order
    pkt->icmp6_seq = seq; 
    pkt->icmp6_cksum = 0;//checksum((uint16_t *) pkt, sizeof(packet));
    //pkt->checksum = 0;

    int bytes = sendto(sock, packet, sizeof(packet), 0 /*flags*/, (sockaddr *)&pingaddr, sizeof(sockaddr_in6));

    if (bytes < 0) {
        std::cout << "the sendto command returned " << bytes << "... we cant send to reciver";
        close(sock);
        throw std::runtime_error("bytes were less than 0");
    }

    else if (bytes != sizeof(packet)) {
        std::cout << "We couldn't write the whole package..\n";
        std::cout << bytes <<"\t versus expect size of: " << sizeof(packet);
        close(sock);
        throw std::runtime_error("we couldn't write the whole packet ");
    }
}

void ping::send_imcp_echo_packet(int sock, sockaddr_in pingaddr, unsigned short seq, unsigned short id) {
    char packet[sizeof(icmphdr)];
    memset(packet, 0, sizeof(packet)); // fill with zeros to ensure no corruption or anything

    icmphdr *pkt = (icmphdr *)packet; // everything inside icmphdr is an int or struct of ints
    pkt->type = ICMP_ECHO; // ICMP ECHO for out, ICMP_ECHO_REPLY will come back to us
    pkt->code = 0; // code 0 = echo reply/req
    pkt->un.echo.id = htons(id & 0xFFFF); // htons converts the unsigned integer hostlong to network bye order
    pkt->un.echo.sequence = seq;
    pkt->checksum = checksum((uint16_t *) pkt, sizeof(packet));
    //pkt->checksum = 0;

    int bytes = sendto(sock, packet, sizeof(packet), 0 /*flags*/, (sockaddr *)&pingaddr, sizeof(sockaddr_in));

    if (bytes < 0) {
        std::cout << "the sendto command returned " << bytes << "... we cant send to reciver";
        close(sock);
        throw std::runtime_error(" ");
    }

    else if (bytes != sizeof(packet)) {
        std::cout << "We couldn't write the whole package..\n";
        std::cout << bytes <<"\t versus expect size of: " << sizeof(packet);
        close(sock);
        throw std::runtime_error(" ");
    }
}


unsigned short ping::listen_for_reply(int sock, sockaddr_in6 pingaddr, unsigned short id) {
    while (1) {
            char inbuf[192]; // TODO: find out what this 192 is
            memset(inbuf, 0, sizeof(inbuf));
            
            int addrlen = sizeof(sockaddr_in);
            int bytes = recvfrom(sock, inbuf /*buffer to save the bytes*/, sizeof(inbuf), 0 /*flags*/, (sockaddr *) &pingaddr, (socklen_t *)&addrlen);
            //int bytes = recv(sock, inbuf /*buffer to save the bytes*/, sizeof(inbuf), 0 /*flags*/); //, (sockaddr *) &pingaddr, (socklen_t *)&addrlen);

            if (bytes < 0) {
                std::cout << "[LISTEN] bytes found: " << bytes << "\n\twe expect a value > 0... continuing\n";
                continue;
            }
            else {
                if (bytes < sizeof(icmp6_hdr)) { // we're getting back an icmp6_hdr wrapped in an ip header TODO cehck
                    std::cout << "[LISTEN] Incorrect read bytes!\n\t... continuing\n";
                }

                ip6_hdr *iph = (ip6_hdr *)inbuf;
                // headerlength is automtically cropped out?????????? 
                
                icmp6_hdr *pkt = (icmp6_hdr *)(inbuf ); // at this point, inbuf + hlen points to the icmp header
                int extracted_id = ntohs(pkt->icmp6_id); // converts unsigned int from network to destination byte order (opposite of the htons we did earlier! ish)
                if (pkt->icmp6_type == ICMP6_ECHO_REPLY) {
                    std::cout << "WE found an IMCP ECHO REPLY!\n";
                    if (extracted_id == id) {
                        std::cout << "The pid's matched!\n";
                        return 1;
                    }
                    else {
                        std::cout << "the pid's did not match.\t " << id << "is what we want, " << extracted_id << "is what we found\n";
                        return 0;
                    }
                }
                else if (pkt->icmp6_type == ICMP6_DST_UNREACH) {
                    std::cout << "[LISTEN] packet type of ICMP6_DEST_UNREACH\n";

                    int offset = sizeof(ip6_hdr) + sizeof(icmp6_hdr) + sizeof(ip6_hdr); // ip6_hdr + icmp hdr going out + another ip6_hdr coming back in? TODO
                    if (((bytes ) - offset) == sizeof(icmp6_hdr))
                    {
                        icmp6_hdr *p = reinterpret_cast<icmp6_hdr *>(inbuf + offset); // extract the original icmp packet
                        if (ntohs(p->icmp6_id) == id) {
                            std::cout << "\tID's match, destination is unreachable\n";
                            return 0;
                        }
                    }
                }
                else {
                    std::cout << "[LISTEN] we got a packet back but it wasnt a reply or an unreachable error...\n";
                    return 0;
                }
            }
        }
}

unsigned short ping::listen_for_reply(int sock, sockaddr_in pingaddr, unsigned short id) {
    while (1) {
            char inbuf[192]; // TODO: find out what this 192 is
            memset(inbuf, 0, sizeof(inbuf));
            
            int addrlen = sizeof(sockaddr_in);
            int bytes = recvfrom(sock, inbuf /*buffer to save the bytes*/, sizeof(inbuf), 0 /*flags*/, (sockaddr *) &pingaddr, (socklen_t *)&addrlen);
            //int bytes = recv(sock, inbuf /*buffer to save the bytes*/, sizeof(inbuf), 0 /*flags*/); //, (sockaddr *) &pingaddr, (socklen_t *)&addrlen);

            if (bytes < 0) {
                std::cout << "[LISTEN] bytes found: " << bytes << "\n\twe expect a value > 0... continuing\n";
                continue;
            }

            else {
                if (bytes < sizeof(iphdr) + sizeof(icmphdr)) { // we're getting back an icmphdr wrapped in an ip header TODO cehck
                    std::cout << "[LISTEN] Incorrect read bytes!\n\t... continuing\n";
                }

                iphdr *iph = (iphdr *)inbuf;
                int hlen = (iph->ihl << 2); // shift left 2
                bytes -= hlen; // subtract the ip header from the bytes, we only care about the icmp info
                
                icmphdr *pkt = (icmphdr *)(inbuf + hlen); // at this point, inbuf + hlen points to the icmp header
                int extracted_id = ntohs(pkt->un.echo.id); // converts unsigned int from network to host byte order (opposite of the htons we did earlier! ish)
                if (pkt->type == ICMP_ECHOREPLY) {
                    std::cout << "WE found an IMCP ECHO REPLY!\n";
                    if (extracted_id == id) {
                        std::cout << "The pid's matched!\n";
                        return 1;
                    }
                    else {
                        std::cout << "the pid's did not match.\t " << id << "is what we want, " << extracted_id << "is what we found\n";
                        return 0;
                    }
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
                }
                else {
                    std::cout << "[LISTEN] we got a packet back but it wasnt a reply or an unreachable error...\n";
                    return 0;
                }
            }
        }
}
int32_t ping::checksum(uint16_t *buf, int32_t len) {
    int32_t nleft = len;
    int32_t sum = 0;
    uint16_t *w = buf;
    uint16_t answer = 0;

    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if(nleft == 1)
    {
        *(uint16_t *)(&answer) = *(uint8_t *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}
