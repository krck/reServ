#ifndef RESERV_CLIENTCONNECTION_H
#define RESERV_CLIENTCONNECTION_H

#include "enums.hpp"
#include "logger.hpp"
#include "types.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace reServ::Client {

using namespace reServ::Common;

class ClientConnection {
  public:
    const rsSocketFd clientSocketfd;
    const std::string clientAddrStr;

  public:
    ClientConnection(rsSocketFd clientSocketfd, rsSocketFd mainEpollFd, const std::string& clientAddrStr, const sockaddr_storage& clientAddr,
                     const epoll_event epollEvent) :
      clientSocketfd(clientSocketfd),
      _mainEpollFd(mainEpollFd), clientAddrStr(clientAddrStr), _clientAddr(clientAddr), _clientEpollEvent(epollEvent),
      _clientState(ClientWebSocketState::Created), _logger(Logger::instance()) {}

    inline bool isState(const ClientWebSocketState state) const { return (_clientState == state); }
    inline ClientWebSocketState getState() const { return _clientState; }

    inline void setHandshakeStarted() { _clientState = ClientWebSocketState::Handshake; }
    inline void setHandshakeCompleted() { _clientState = ClientWebSocketState::Open; }
    inline void setClosing() { _clientState = ClientWebSocketState::Closing; }

    ~ClientConnection() {
        _logger.log(LogLevel::Debug, ("Client connection closed: " + clientAddrStr));

        // Shutdown the TCP/Socket connection (and remove the client from the epoll instance)
        epoll_ctl(_mainEpollFd, EPOLL_CTL_DEL, clientSocketfd, nullptr);
        close(clientSocketfd);
        // if(shutdown(clientSocketfd, SHUT_RDWR) < 0) {
        //     _logger.log(LogLevel::Error, ("Failed to shutdown client socket: " + _clientAddrStr));
        //     _clientState = ClientWebSocketState::Error;
        // }
    };

  private:
    const rsSocketFd _mainEpollFd;
    const sockaddr_storage _clientAddr;
    const epoll_event _clientEpollEvent;
    ClientWebSocketState _clientState;
    Logger& _logger;
};

} // namespace reServ::Client

#endif
