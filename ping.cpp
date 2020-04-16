#include "ping.h"
#include <arpa/inet.h>
#include <sys/socket.h>
/**
 * create an ifdef linux icmp.h is avalible
 */
// #include <netinet/ip_icmp.h> 
#include <iostream>
#include <netinet/in.h> // sockaddr_in
#include <cstdio>
#include <cstdlib>
#include <stdint.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#include <time.h>
#include <errno.h>
#include <cstring> // string arrays
#include <netdb.h>
#include <unistd.h> // for closing sockets

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

void ping::start_ping(std::string _host) {
             
    /*
     * domain = 
     *   AF_INET for ipv4
     *   AF_INET for ipv6
     *
     * type= sock_raw -- we aren't using TCP or UDP
     * protocol = same number that appears on the protocol field in the IP header
     *   for ipv4, this number is 0
     */

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock < 0) { // an error occured
        close(sock);
        throw std::runtime_error(" couldnt make socket, run as root(?)");
    }

    /*
     * each packet needs a UID, that way we can retrive the right on when listening for echo backs
     *  - using process ID for this TODO: check that
     *      - wrong, this de-esclates the root program so the pid is accessable by the user
     */
    setuid(getuid());
    
    /*
     * sockaddr_in fields: {sin_family, sin_port, sin_addr, sin_zero}
     */
    sockaddr_in pingaddr; 
    memset(&pingaddr, 0, sizeof(sockaddr_in)); // TODO: see if you can remove this (i think its for sin_zero)
    pingaddr.sin_family = AF_INET;
     
    /*
     *TODO: remove this, i think its just getting the current machine's ip address in a really complicated way
     * or, its a way to verify the destination (i think this is more correct)
     */
    std::cout << _host << "\n";

    hostent *h = gethostbyname(_host.c_str());
    if(not h)
    {
        printf("Failed to get host by name!\n");
        close(sock);
        exit(1);
    }
    
    memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr)); // copy host address into .sin_addr

    /*
     * strange error:
     * pid > 5 numbers breaks
     * temp solution
     */
    int pid = getpid(); // this is the id for the header

    while (pid/ 100000 != 0) {
        pid /= 10;
    }
    std::cout << " the pid is " << pid << "\n";
    
    /*
     * when listening for an echo, this is everything we want to filter out
     * TODO: make this not bitwise bullshit
     */
    icmp_filter filter;
    filter.data = ~((1<<ICMP_SOURCE_QUENCH) |
                    (1<<ICMP_DEST_UNREACH) |
                    (1<<ICMP_TIME_EXCEEDED) |
                    (1<<ICMP_REDIRECT) |
                    (1<<ICMP_ECHOREPLY));
    /*
     * >... manipulate options for the socket referred to by the file descriptor sockfd
     * >... 
       Raw socket options can be set  with  getsockopt  and  read
       with getsockopt by passing the SOL_RAW family flag.
     */
    if(setsockopt(sock, SOL_RAW, ICMP_FILTER, (char *)&filter, sizeof(filter)) < 0) {
        std::cout << "couldn't set socket options... dont know why";
        throw std::runtime_error(" ");
    }

    unsigned short num_recieved = 0;

    // SEDING THE PACKET!!!
    for (int i = 0; i < 5; i++) {
        std::cout << "attempting ping #" << i+1 << "\n";
        send_imcp_echo_packet(sock, pingaddr, i, pid);
        num_recieved += listen_for_reply(sock, pingaddr, pid);
    }
    std::cout << "we recived " << num_recieved << " packets back";
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

