#include "ping.h"
#include <arpa/inet.h>
#include <sys/socket.h>
/**
 * create an ifdef linux icmp.h is avalible
 */
// #include <netinet/ip_icmp.h> 
#include <netinet/icmp6.h>
#include <netinet/ip6.h>


#include <iostream>
#include <netinet/in.h> // sockaddr_in
#include <cstdio>
#include <cstdlib>
#include <stdint.h>
//#include <linux/icmp.h>
//#include <linux/icmpv6.h>
//#include <linux/ip.h>
//#include <linux/ipv6.h> shouldn't be using these allegedly

#include <cstring> // string arrays
#include <unistd.h> // for closing sockets
#include <errno.h>


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

void ping::start_ping(std::string dest) {
             
    /*
     * domain = 
     *   AF_INET for ipv4
     *   AF_INET for ipv6
     *
     * type= sock_raw -- we aren't using TCP or UDP
     * protocol = same number that appears on the protocol field in the IP header
     *   for ipv4, this number is 0
     */

    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

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
    sockaddr_in6 pingaddr; 
    pingaddr.sin6_family = AF_INET6;
     
    /*
     *TODO: remove this, i think its just getting the current machine's ip address in a really complicated way
     * or, its a way to verify the destination (i think this is more correct)
     */
    std::cout << dest << "\n";

    struct sockaddr_in6 host;
    inet_pton(AF_INET6, dest.c_str(), &host.sin6_addr); // convert ip address from text to binary

    pingaddr.sin6_addr = host.sin6_addr;
    std::cout << pingaddr.sin6_addr.s6_addr <<"\n";

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
    icmp6_filter filter;
    //(1<<ICMP6_SOURCE_QUENCH)  is now depricated
    /* 
    filter.data = ~((1<<ICMP6_DEST_UNREACH) |
                    (1<<ICMP6_TIME_EXCEED) |
                    (1<<ICMP6_ECHO_REPLY));
                */
    /*
     * >... manipulate options for the socket referred to by the file descriptor sockfd
     * >... 
       Raw socket options can be set  with  getsockopt  and  read
       with getsockopt by passing the SOL_RAW family flag.

TODO: change IPPROTTO back to SOL_RAW?
     */
    if(setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, (char *)&filter, sizeof(filter)) < 0) {
                printf ("Error %d opening socket.\n", errno);

        throw std::runtime_error("couldn't set socket options... dont know why");
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

void ping::send_imcp_echo_packet(int sock, sockaddr_in6 pingaddr, unsigned short seq, unsigned short id) {
    char packet[sizeof(icmp6_hdr)];
    memset(packet, 0, sizeof(packet)); // fill with zeros to ensure no corruption or anything
    
    icmp6_hdr *pkt = (icmp6_hdr *)packet; // everything inside icmp6_hdr is an int or struct of ints
    pkt->icmp6_type = ICMP6_ECHO_REQUEST; // ICMP6 ECHO for out, ICMP6_ECHO_REPLY will come back to us
    pkt->icmp6_code = 0; // code 0 = echo reply/req
    pkt->icmp6_id = htons(id & 0xFFFF); // htons converts the unsigned integer hostlong to network bye order
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
                int extracted_id = ntohs(pkt->icmp6_id); // converts unsigned int from network to host byte order (opposite of the htons we did earlier! ish)
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

