#ifndef RESERV_CLIENTCONNECTION_H
#define RESERV_CLIENTCONNECTION_H

#include "types.hpp"

#include <string>
#include <sys/socket.h>

namespace reServ::Client {

using namespace reServ::Common;

struct ClientConnection {
  public:
    // Core Connection data
    const int clientSocketfd;
    const sockaddr_storage clientAddr;
    const std::string clientAddrStr;
    // Variable Connection data
    rsUInt64 lastPingTimestamp = 0;
    bool awaitingPong          = false;

  public:
    ClientConnection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr) :
      clientSocketfd(clientSocketfd), clientAddr(clientAddr), clientAddrStr(clientAddrStr) {}

    ~ClientConnection() = default;
};

} // namespace reServ::Client

#endif
