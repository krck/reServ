#ifndef RESERV_SERVERCONFIG_H
#define RESERV_SERVERCONFIG_H

#include "enums.hpp"

#include <string>

namespace reServ::Server {

using namespace reServ::Common;

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
    OutputBehavior outputBehavior = OutputBehavior::Echo; // 0: Echo, 1: Broadcast, 2: Custom

    // Static/Hardcoded configuration
    static const int recvBufferSize  = 4096; // 4 KiB - Gets doubled dynamically if needed on recv
    static const int frameHeaderSize = 14;   // WebSocket Frame has a (min 2) max 14 bytes header
};

} // namespace reServ::Server

#endif
