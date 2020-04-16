## about
- written in c++
## requirements
- [X] accept a hostname or IP address as terminal arguments
- [X] send ICMP echo requests in an infinite loop
- report loss and rtt times
## extra credit
- support for ipv4 & 6
    - nmap makes you throw a -6 flag
- allow to set TTL as an argument
- any additional features
---
## scratch pad
- commands from ping
    - `-a` audible ping
    - `-c` count, the amount of ping packets to send
    - `-D` print timestamps
    - `-h` help
    - `-m` mark
    - `-q` queit, only show output at the end
    - `-p` packet size
    - `-V` version

---
## status
- [X] ping ipv4 hosts
- [X] listen for and filter responses
- [ ] support ipv6
- [ ] command line
    - [ ] sanitization
    - [ ] show help logs
    - [ ] -a support
    - [ ] -c support
    - [ ] -D time stamp support
    - [ ] -V version
- [ ] #ifdef if `<linux/icmp.h>` and `<linux/in.h>` are avaliable, `<netinet/ip_icmp.h>` if not
- [ ] ncurses support ??
- [ ] fix pid issue
- [ ] fix sendto and recvfrom
- [ ] reduce use of cstrings
- [ ] init structs inline
