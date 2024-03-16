#include "server.hpp"

using namespace reServ::Server;
using namespace reServ::Common;

int main(int argc, char* argv[]) {
    ServerConfig config;

    try {
        std::string argKey, argVal;
        for(int i = 1; i < argc; i += 2) {
            argKey = argv[i];
            argVal = argv[i + 1];
            std::cout << argKey << " " << argVal << std::endl;

            if(argKey == "--port") {
                config.port = std::stoi(argVal);
            } else if(argKey == "--wsVersion") {
                config.wsVersion = argVal;
            } else if(argKey == "--maxConnectionBacklog") {
                config.maxConnectionBacklog = std::stoi(argVal);
            } else if(argKey == "--maxEpollEvents") {
                config.maxEpollEvents = std::stoi(argVal);
            } else if(argKey == "--maxPayloadLength") {
                config.maxPayloadLength = std::stoi(argVal);
            } else if(argKey == "--idleTimeout") {
                config.idleTimeout = std::stoi(argVal);
            } else if(argKey == "--compression") {
                config.compression = std::stoi(argVal);
            } else if(argKey == "--closeOnBackPressureLimit") {
                config.closeOnBackPressureLimit = std::stoi(argVal) != 0;
            } else if(argKey == "--resetIdleTimeoutOnSend") {
                config.resetIdleTimeoutOnSend = std::stoi(argVal) != 0;
            } else if(argKey == "--sendPingsAutomatically") {
                config.sendPingsAutomatically = std::stoi(argVal) != 0;
            } else if(argKey == "--outputBehavior") {
                config.outputBehavior = static_cast<OutputBehavior>(std::stoi(argVal));
            }
        }
    } catch(const std::exception& e) {
        Logger::instance().log(LogLevel::Error, "Can not parse args - using default values - Error: " + std::string(e.what()));
    }

    // Start and run the server
    Logger::instance().log(LogLevel::Info, "Server config valid. Starting...");
    Server tcpServer(config);
    return tcpServer.run();
}
