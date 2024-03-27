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

  public:
    ClientConnection(rsSocketFd clientSocketfd, rsSocketFd mainEpollFd, const sockaddr_storage& clientAddr) :
      clientSocketfd(clientSocketfd), _mainEpollFd(mainEpollFd), _clientAddr(clientAddr), _logger(Logger::instance()) {
        // Extract the client IP address as readable string
        if(clientAddr.ss_family == AF_INET) {
            // IP v4 Address
            struct sockaddr_in* addr_v4 = (struct sockaddr_in*)&clientAddr;
            _clientAddrStr              = std::string(inet_ntoa(addr_v4->sin_addr));
        } else {
            // IP v6 Address
            char a[INET6_ADDRSTRLEN] { '\0' };
            struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)&clientAddr;
            inet_ntop(AF_INET6, &(addr_v6->sin6_addr), a, INET6_ADDRSTRLEN);
            _clientAddrStr = std::string(a);
        }

        // Finally set the client state to created
        _clientState = ClientWebSocketState::Created;
    }

    inline std::string getClientAddr() const { return _clientAddrStr; }
    inline ClientWebSocketState getState() const { return _clientState; }
    inline bool isState(const ClientWebSocketState state) const { return (_clientState == state); }

    inline void setHandshakeStarted() { _clientState = ClientWebSocketState::Handshake; }
    inline void setHandshakeCompleted() { _clientState = ClientWebSocketState::Open; }
    inline void setClosingFromServer() { _clientState = ClientWebSocketState::ClosingServerTrigger; }
    inline void setClosingFromClient() { _clientState = ClientWebSocketState::ClosingClientTrigger; }
    inline void setCloseWaitForClient() { _clientState = ClientWebSocketState::ClosingServerWait; }

    ~ClientConnection() {
        _logger.log(LogLevel::Debug, ("Client connection closed: " + _clientAddrStr));

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
    ClientWebSocketState _clientState;
    std::string _clientAddrStr;
    Logger& _logger;
};

} // namespace reServ::Client

#endif
