#ifndef RESERV_SERVERCONFIG_H
#define RESERV_SERVERCONFIG_H

#include <string>

namespace reServ::Server {

struct ServerConfig {
    // Dynamic/Args configuration
    int port                      = 8080;
    std::string wsVersion         = "13";
    int maxConnectionBacklog      = 16;
    int maxEpollEvents            = 128;
    int maxPayloadLength          = 16 * 1024 * 1024;
    int idleTimeout               = 16;
    bool closeOnBackPressureLimit = false;
    bool resetIdleTimeoutOnSend   = false;
    bool sendPingsAutomatically   = true;
    // int compression;

    // Static/Hardcoded configuration
    static const int recvBufferSize = 1024;
};

} // namespace reServ::Server

#endif
