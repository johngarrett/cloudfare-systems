#include <string>
#include "ping.h"
#include "cxxopts.hpp"

int main(int argc, char* argv[]) {
    cxxopts::Options options(argv[0]);

    options.add_options()
        ("a,audio", "audible ping", cxxopts::value<bool>()->default_value("false"))
        ("c,count","the amount of ping packets to send", cxxopts::value<std::string>())
        ("t,timestamps", "print time stamps", cxxopts::value<bool>()->default_value("true"))
        ("h,help", "display the help menu")
        ("q,quiet", "only show output summary", cxxopts::value<bool>()->default_value("true"))
        ("s,size", "set the packet size to send", cxxopts::value<unsigned int>());

    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
        std::cout << options.help() << "\n";
        exit(0);
    }

    std::string lastArg = std::string(argv[argc - 1]);
    if (argc == 1 || lastArg.size() == 0) {
        std::cout << "Usage: " << argv[0] << " [options] {destination}\n";
        exit(0);
    }
    
  //  std::string _host = argv[1]; // TODO: sanatize
   // ping::start_ping(_host);
    return 0;
}

