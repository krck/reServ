#include "server.hpp"
#include "wsConfig.hpp"

using namespace reServ;

int main(int argc, char* argv[]) {
    WsConfig config;

    try {
        std::string argKey, argVal;
        for(int i = 1; i < argc; i += 2) {
            argKey = argv[i];
            argVal = argv[i + 1];
            std::cout << argKey << " " << argVal << std::endl;

            if(argKey == "--port") {
                config.port = std::stoi(argVal);
            } else if(argKey == "--maxConnectionBacklog") {
                config.maxConnectionBacklog = std::stoi(argVal);
            } else if(argKey == "--maxEpollEvents") {
                config.maxEpollEvents = std::stoi(argVal);
            } else if(argKey == "--maxPayloadLength") {
                config.maxPayloadLength = std::stoi(argVal);
            } else if(argKey == "--idleTimeout") {
                config.idleTimeout = std::stoi(argVal);
            } else if(argKey == "--closeOnBackpressureLimit") {
                config.closeOnBackpressureLimit = std::stoi(argVal) != 0;
            } else if(argKey == "--resetIdleTimeoutOnSend") {
                config.resetIdleTimeoutOnSend = std::stoi(argVal) != 0;
            } else if(argKey == "--sendPingsAutomatically") {
                config.sendPingsAutomatically = std::stoi(argVal) != 0;
            }
        }
    } catch(const std::exception& e) {
        Logger::instance().log(LogLevel::Error, "Can not parse args - using default values - Error: " + std::string(e.what()));
    }

    Server tcpServer(config);
    return tcpServer.run();
}
