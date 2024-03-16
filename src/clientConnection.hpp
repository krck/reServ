#ifndef RESERV_CLIENTCONNECTION_H
#define RESERV_CLIENTCONNECTION_H

#include "types.hpp"

#include <string>
#include <sys/socket.h>

namespace reServ::Client {

struct ClientConnection {
  public:
    const int clientSocketfd;
    const sockaddr_storage clientAddr;
    const std::string clientAddrStr;

  public:
    ClientConnection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr) :
      clientSocketfd(clientSocketfd), clientAddr(clientAddr), clientAddrStr(clientAddrStr) {}

    ~ClientConnection() = default;
};

} // namespace reServ::Client

#endif
