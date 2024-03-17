#ifndef RESERV_CONFIGSERVICE_H
#define RESERV_CONFIGSERVICE_H

#include "enums.hpp"
#include "logger.hpp"

#include <string>

namespace reServ::Common {

//
// Server Config
//
struct ServerConfig {
    // Dynamic/Args configuration
    int port                      = 8080;
    std::string wsVersion         = "13";
    int maxConnectionBacklog      = 16;
    int maxEpollEvents            = 128;
    int maxPayloadLength          = 10485760; // 10 MiB as max message size
    int idleTimeout               = 16;
    int compression               = 0;
    bool closeOnBackPressureLimit = false;
    bool resetIdleTimeoutOnSend   = false;
    bool sendPingsAutomatically   = true;
    OutputMethod outputMethod     = OutputMethod::Echo; // 0: Echo, 1: Broadcast, 2: Custom

    // Static/Hardcoded configuration
    static const int recvBufferSize  = 4096; // 4 KiB - Gets doubled dynamically if needed on recv
    static const int frameHeaderSize = 14;   // WebSocket Frame has a (min 2) max 14 bytes header
};

//
// Config Service (Singleton)
//
class ConfigService {
  public:
    static ConfigService& instance() {
        // Instantiated on first use - Guaranteed to be destroyed
        static ConfigService instance;
        return instance;
    }

    // Get the server configuration
    const ServerConfig& getServerConfig() const { return _serverConfig; }

    // Update ServerConfig from the command-line arguments
    const ServerConfig& updateServerConfigFromArgs(int argc, char* argv[]) {
        try {
            std::string argKey, argVal;
            for(int i = 1; i < argc; i += 2) {
                argKey = argv[i];
                argVal = argv[i + 1];

                if(argKey == "--port" || argKey == "--p") {
                    _serverConfig.port = std::stoi(argVal);
                } else if(argKey == "--wsVersion" || argKey == "--v") {
                    _serverConfig.wsVersion = argVal;
                } else if(argKey == "--maxConnectionBacklog") {
                    _serverConfig.maxConnectionBacklog = std::stoi(argVal);
                } else if(argKey == "--maxEpollEvents") {
                    _serverConfig.maxEpollEvents = std::stoi(argVal);
                } else if(argKey == "--maxPayloadLength") {
                    _serverConfig.maxPayloadLength = std::stoi(argVal);
                } else if(argKey == "--idleTimeout") {
                    _serverConfig.idleTimeout = std::stoi(argVal);
                } else if(argKey == "--compression") {
                    _serverConfig.compression = std::stoi(argVal);
                } else if(argKey == "--closeOnBackPressureLimit") {
                    _serverConfig.closeOnBackPressureLimit = std::stoi(argVal) != 0;
                } else if(argKey == "--resetIdleTimeoutOnSend") {
                    _serverConfig.resetIdleTimeoutOnSend = std::stoi(argVal) != 0;
                } else if(argKey == "--sendPingsAutomatically") {
                    _serverConfig.sendPingsAutomatically = std::stoi(argVal) != 0;
                } else if(argKey == "--outputBehavior") {
                    _serverConfig.outputMethod = static_cast<OutputMethod>(std::stoi(argVal));
                }
            }
            return _serverConfig;
        } catch(const std::exception& e) {
            Logger::instance().log(LogLevel::Error, "Can not parse args - using default values - Error: " + std::string(e.what()));
            return _serverConfig;
        }
    }

    ~ConfigService() {}

  private:
    // Private ctor so no other object can be created
    ConfigService() : _serverConfig(ServerConfig()), _logger(Logger::instance()) {}

    // Delete copy-constructor and copy-assignment operator
    ConfigService(ConfigService const&)  = delete;
    void operator=(ConfigService const&) = delete;

  private:
  private:
    ServerConfig _serverConfig;
    Logger& _logger;
};

} // namespace reServ::Common

#endif
