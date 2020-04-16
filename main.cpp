#include <string>
#include "ping.h"

int main(int argc, char* argv[]) {
    std::string _host = argv[1]; // TODO: sanatize
    ping::start_ping(_host);
    return 0;
}
