Ping {
    public:
        static ping(params....)
        {
            validate_address()
            checksum()
            //construct ICMP packet

            while cont not exceeded if specified:
                send_packet()
                listen()

            // print out stats
        }

    private:
        unsigned int checksum() 
        {
        }

        void validate_address()
        {
        }
        
        void listen()
        {
        }


};

struct ICMP_PACKET
{
    // TODO: shrink these types
    unsigned int type;
    unsigned int code;
    unsigned int checksum;
    unsigned int id;
    unsigned int seq;
    char* data;
}
