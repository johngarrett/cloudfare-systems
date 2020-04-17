#include <string>
#include "ping.hpp"
#include "include/cxxopts.hpp"

int main(int argc, char* argv[]) {
    cxxopts::Options options(argv[0]);

    options.add_options()
        ("a,audio", "audible ping", cxxopts::value<bool>()->default_value("false"))
        ("c,count","the amount of ping packets to send", cxxopts::value<unsigned int>())
        ("t,timestamps", "print time stamps", cxxopts::value<bool>()->default_value("true"))
        ("h,help", "display the help menu")
        ("q,quiet", "only show output summary", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose", "print all the information we can", cxxopts::value<bool>()->default_value("false"))
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
    
    ping::Parameters p; 
    ping::start_ping(lastArg);
    return 0;
}

