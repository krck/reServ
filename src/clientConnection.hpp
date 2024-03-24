#ifndef RESERV_CLIENTCONNECTION_H
#define RESERV_CLIENTCONNECTION_H

#include "types.hpp"

#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>

namespace reServ::Client {

using namespace reServ::Common;

struct ClientConnection {
  public:
    // Core Connection data
    const int clientSocketfd;
    const sockaddr_storage clientAddr;
    const std::string clientAddrStr;
    const epoll_event epollEvent;

  public:
    ClientConnection(const int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr, const epoll_event& epollEvent) :
      clientSocketfd(clientSocketfd), clientAddr(clientAddr), clientAddrStr(clientAddrStr), epollEvent(epollEvent) {}

    ~ClientConnection() = default;
};

} // namespace reServ::Client

#endif
