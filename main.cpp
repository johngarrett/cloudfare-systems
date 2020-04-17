#include <stdexcept>
#include <string>
#include "ping.hpp"
#include "include/cxxopts.hpp"

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options(argv[0]);

        options.add_options()
            ("a,audio", "audible ping", cxxopts::value<bool>()->default_value("false"))
            ("c,count","the amount of ping packets to send", cxxopts::value<unsigned int>()->default_value("5"))
            ("T,timestamps", "print time stamps", cxxopts::value<bool>()->default_value("true"))
            ("h,help", "display the help menu")
            ("q,quiet", "only show output summary", cxxopts::value<bool>()->default_value("false"))
            ("v,verbose", "print all the information we can", cxxopts::value<bool>()->default_value("false"))
            ("s,size", "set the packet size to send", cxxopts::value<unsigned int>()->default_value("64"))
            ("t,ttl", "set the IP Time to Live", cxxopts::value<int>()->default_value("255"))
            ("d,delay", "time (in seconds) to wait between pings", cxxopts::value<unsigned short>()->default_value("1"));

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
        
        ping::Parameters p{ result["audio"].as<bool>(),
                            result["quiet"].as<bool>(),
                            result["verbose"].as<bool>(),
                            result["timestamps"].as<bool>(),
                            int(result["count"].as<unsigned int>()),
                            result["size"].as<unsigned int>(),
                            result["ttl"].as<int>(),
                            result["delay"].as<unsigned short>() };
        
        ping::start_ping(lastArg, p);
    } catch (cxxopts::argument_incorrect_type& e) {
        std::cout << "Error running program, incorrect usage.\n\t Type -h or --help for help\n";
    } catch (std::invalid_argument& e) {
        std::cout << "Error running program, invalid argument was sent.\n\t" << e.what() << "\n";
    } catch (std::runtime_error& e) {
        std::cout << "Error running program: \n\t" << e.what() << "\n";
    }
}

