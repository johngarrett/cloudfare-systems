#include <string>

class ping
{
    public:
        static void start_ping(std::string _host);
    private:
        static int32_t checksum(uint16_t *buf, int32_t len);
};
