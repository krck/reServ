#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include "clientConnection.hpp"
#include "configService.hpp"
#include "enums.hpp"
#include "helpers.hpp"
#include "logger.hpp"
#include "serverConnectionHandler.hpp"
#include "serverInputHandler.hpp"
#include "serverOutputHandler.hpp"
#include "types.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <stdexcept>
#include <sys/epoll.h>
#include <unistd.h>
#include <unordered_map>

namespace reServ::Server {

using namespace reServ::Client;
using namespace reServ::Common;

class Server {
  public:
    Server() :
      _epollfd(-1), _mainSocketfd(-1), _config(ConfigService::instance().getServerConfig()), _serverAddrListFull(nullptr), _clientCloseQueue(),
      _clientMessageQueue(), _clientConnections(), _serverConnectionHandler(ServerConnectionHandler()), _serverOutputHandler(ServerOutputHandler()),
      _serverInputHandler(ServerInputHandler()), _logger(Logger::instance()) {
        // Reserve some heap space to reduce memory allocation overhead when new clients are connected
        _clientConnections.reserve(200);
    }

    bool run() {
        try {
            // Create and bind the main server (listening) socket
            if((_mainSocketfd = createAndBindMainServerSocket()) <= 0)
                throw std::runtime_error("Failed to create and bind a socket");

            // Put the Server socket in listening mode, waiting to accept new connections
            // (If a connection request arrives when the backlog is full, it will get ECONNREFUSED)
            if(listen(_mainSocketfd, _config.maxConnectionBacklog) < 0)
                throw std::runtime_error("Failed to initialize listening");

            // Create the epoll instance
            if((_epollfd = epoll_create1(0)) <= 0)
                throw std::runtime_error("Failed to create epoll instance");

            epoll_event event;
            event.events  = EPOLLIN | EPOLLET;
            event.data.fd = _mainSocketfd;
            epoll_ctl(_epollfd, EPOLL_CTL_ADD, _mainSocketfd, &event);

            // -------------------------------------------------------------------------------------
            // Start the MAIN EVENT LOOP (that currently can never finish, just crash via exception)
            // -------------------------------------------------------------------------------------
            _logger.log(LogLevel::Info, "Server running: Main Socket listening on port " + std::to_string(_config.port));
            while(true) {
                // 1. Handle INPUT (new client connections and existing client activity)
                std::vector<epoll_event> events(_config.maxEpollEvents);
                int numEvents = epoll_wait(_epollfd, &events[0], _config.maxEpollEvents, -1);
                for(int i = 0; i < numEvents; i++) {
                    if(events[i].data.fd == _mainSocketfd) {
                        // New client connection (if the "write" event is on the main listening socket)
                        coreConnectionCreateHandler();
                    } else if(_clientConnections.find(events[i].data.fd) != _clientConnections.end()) {
                        // Existing client activity (if the "write" event is on any other (client) socket)
                        _logger.log(LogLevel::Debug, "Client activity on socket: " + std::to_string(events[i].data.fd));
                        coreInputHandler(_clientConnections[events[i].data.fd].get());
                    }
                }

                // 2. Handle OUTPUT (send new messages to the clients)
                while(!_clientMessageQueue.empty()) {
                    ClientMessage* message = _clientMessageQueue.front().get();
                    coreOutputHandler(message);
                    _clientMessageQueue.pop();
                }

                // 3. Handle CLOSE CONDITIONS (connections that encountered an error, timeout, etc.)
                while(!_clientCloseQueue.empty()) {
                    const CloseCondition& condition = _clientCloseQueue.front();
                    coreConnectionCloseHandler(condition);
                    _clientCloseQueue.pop();
                }
            }
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "Server: " + std::string(e.what()));
            return false;
        }
    }

    ~Server() {
        // Free the linked list of Server addrinfos
        freeaddrinfo(_serverAddrListFull);

        // Stop any communication with "shutdown" and free the socket descriptor with "close"
        // shutdown(_mainSocketfd, SHUT_RDWR);
        close(_mainSocketfd);
        close(_epollfd);

        _logger.log(LogLevel::Info, "Server stopped. Main Socket closed.");
    }

  private:
    int createAndBindMainServerSocket() {
        addrinfo* serverAddr;
        addrinfo serverHints;
        int socketOptions = 0;
        int serverSocket  = 0;
        int addrStatus    = 0;

        // Helper struct for getaddrinfo() which will create the servers address configuration
        std::memset(&serverHints, 0, sizeof(serverHints));
        serverHints.ai_flags    = AI_PASSIVE;  // AI_PASSIVE to automatically fill in the server IP
        serverHints.ai_family   = AF_UNSPEC;   // AF_UNSPEC to enable IPv4/IPv6
        serverHints.ai_socktype = SOCK_STREAM; // TCP

        // Get the Servers IP address structures, based on the pre-configured "serverHints" (IPv4/IPv6, auto fill, TCP)
        // (All the Servers IP addresses that match the hint config will be stored in a linked-list struct "_serverAddrList")
        if((addrStatus = getaddrinfo(nullptr, std::to_string(_config.port).c_str(), &serverHints, &_serverAddrListFull)) != 0)
            return -1;

        // Loop through all the Server IP address results and bind a new socket to the first possible
        for(serverAddr = _serverAddrListFull; serverAddr != nullptr; serverAddr = serverAddr->ai_next) {
            // Create a new socket based on the current serverAddress, which was configured based on the "serverHints"
            if((serverSocket = socket(serverAddr->ai_family, serverAddr->ai_socktype, serverAddr->ai_protocol)) < 0) {
                continue;
            }
            // Attach socket to the defined Port (forcefully - can prevent "Address already in use" errors)
            if(setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &socketOptions, sizeof(socketOptions)) < 0) {
                close(serverSocket);
                continue;
            }
            // Bind socket to the local IP address and the configured Port/Protocol
            if(bind(serverSocket, serverAddr->ai_addr, serverAddr->ai_addrlen) < 0) {
                close(serverSocket);
                continue;
            }
            // In case a socket could be created and bound to a address,
            // stop the loop and use that socket as the main server socket
            break;
        }

        if(serverAddr == nullptr || serverSocket < 0)
            return -1;

        // Set the server socket to non-blocking mode
        // (For edge-triggered epoll, nonblocking sockets MUST be used)
        fcntl(serverSocket, F_SETFL, O_NONBLOCK);

        return serverSocket;
    }

    bool coreConnectionCreateHandler() {
        int newClientSocketFd = -1;
        try {
            // Accept a new connection on the main/listening socket
            // (creates a new client socket and establishes the connection)
            sockaddr_storage clientAddr = {};
            socklen_t clientAddrSize    = sizeof(clientAddr);
            newClientSocketFd           = accept(_mainSocketfd, (sockaddr*)&clientAddr, &clientAddrSize);
            if(newClientSocketFd < 0) {
                _logger.log(LogLevel::Error, "Failed to accept new client connection");
                return false;
            }

            auto clientAddrStr = extractIpAddrString(&clientAddr);

            // Receive initial data from the client
            std::vector<rsByte> recvBuffer(_config.recvBufferSize);
            ssize_t bytesRead = recv(newClientSocketFd, &recvBuffer[0], _config.recvBufferSize, 0);
            const std::string request(recvBuffer.begin(), recvBuffer.end());
            if(bytesRead > 0) {
                auto response = _serverConnectionHandler.handleHandshakeRequest(request);
                std::vector<rsByte> respBytes(response.begin(), response.end());

                // Set the client socket to non-blocking mode and add it to the epoll instance
                fcntl(newClientSocketFd, F_SETFL, O_NONBLOCK);
                epoll_event event;
                event.data.fd = newClientSocketFd;
                event.events  = EPOLLIN | EPOLLET; // read events in edge-triggered mode
                epoll_ctl(_epollfd, EPOLL_CTL_ADD, newClientSocketFd, &event);

                // Send the handshake response to the client and save the new client connection
                ssize_t bytesWritten = sendToSocket(newClientSocketFd, respBytes);
                if(bytesWritten >= 0) {
                    ClientConnection newConnection { newClientSocketFd, clientAddr, clientAddrStr };
                    _clientConnections.insert({ newClientSocketFd, std::make_unique<ClientConnection>(newConnection) });
                    _logger.log(LogLevel::Info, "Client Connection established: " + clientAddrStr);
                    return true;
                } else {
                    auto err = ("Failed to send handshake response to client: " + clientAddrStr);
                    _clientCloseQueue.push({ newClientSocketFd, false, err });
                    _logger.log(LogLevel::Error, err);
                }
            } else {
                // Close the connection in case recv returned 0, or a WebSocket/HTTP header was not found
                auto err = ("Client Connection closed from remote: " + clientAddrStr);
                _clientCloseQueue.push({ newClientSocketFd, false, err });
                _logger.log(LogLevel::Error, err);
            }

            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "Handle connection: " + std::string(e.what()));
            return false;
        }
    }

    bool coreInputHandler(const ClientConnection* const client) {
        try {
            // Receive incoming data, until there is no more data to read on the client socket
            std::vector<rsByte> recvBuf(_config.recvBufferSize);
            rsInt64 bytesRecv = 0; // Overall bytes received (incoming message)
            rsInt64 tmpRecv   = 0; // "Batch" Bytes received in one recv call
            while((tmpRecv = recv(client->clientSocketfd, &recvBuf[bytesRecv], recvBuf.size() - bytesRecv, 0)) > 0) {
                bytesRecv += tmpRecv;

                // Resize the buffer if its full (scale by always doubling the size to reduce allocation overhead)
                // TODO: This could be easily abused by a client to allocate a lot of memory on the server!!!!
                if(bytesRecv == (rsInt64)recvBuf.size())
                    recvBuf.resize(recvBuf.size() * 2);
            }

            // while(true) {
            //     tmpRecv = recv(client->clientSocketfd, &recvBuf[bytesRecv], recvBuf.size() - bytesRecv, 0);

            //     // Handle recv errors or connection closure
            //     if(tmpRecv == 0) {
            //         _clientCloseQueue.push({ client->clientSocketfd, true, "NORMAL_CLOSURE", WsCloseCode::NORMAL_CLOSURE });
            //         return false;
            //     } else if(tmpRecv < 0) {
            //         _clientCloseQueue.push({ client->clientSocketfd, true, "ABNORMAL_CLOSURE", WsCloseCode::ABNORMAL_CLOSURE });
            //         return false;
            //     }

            //     bytesRecv += tmpRecv;

            //     // Check if we have a complete WebSocket frame
            //     if(_serverInputHandler.parseFrameLength(recvBuf)) {
            //         break;
            //     }

            //     // Resize the buffer if its full (scale by always doubling the size to reduce allocation overhead)
            //     if(bytesRecv == (rsInt64)recvBuf.size()) {
            //         // Check for buffer overflow (if buffer is too large, close the connection)
            //         if(recvBuf.size() * 2 > (_config.maxPayloadLength + _config.frameHeaderSize)) {
            //             _clientCloseQueue.push({ client->clientSocketfd, true, "ABNORMAL_CLOSURE", WsCloseCode::ABNORMAL_CLOSURE });
            //             return false;
            //         }

            //         recvBuf.resize(recvBuf.size() * 2);
            //     }
            // }

            if(bytesRecv > 0) {
                _logger.log(LogLevel::Debug, "Received message: " + std::to_string(bytesRecv));

                auto result = _serverInputHandler.parseWsDataFrame(client->clientSocketfd, recvBuf);
                if(std::holds_alternative<ClientMessage>(result)) {
                    _clientMessageQueue.push(std::make_unique<ClientMessage>(std::get<ClientMessage>(result)));
                    //_logger.log(LogLevel::Info, "Received message: " + message.payloadPlainText);
                    return true;
                } else {
                    // Close the connection in case the input handler returned a CloseCondition
                    _clientCloseQueue.push(std::get<CloseCondition>(result));
                    return false;
                }
            } else if(bytesRecv == 0) {
                // In case recv returns 0, the connection should be closed (client has closed)
                _clientCloseQueue.push({ client->clientSocketfd, true, "NORMAL_CLOSURE", WsCloseCode::NORMAL_CLOSURE });
                return true;
            } else {
                // In case recv return -1, there was an error and the connection should be closed
                _clientCloseQueue.push({ client->clientSocketfd, true, "ABNORMAL_CLOSURE", WsCloseCode::ABNORMAL_CLOSURE });
                return false;
            }
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            _clientCloseQueue.push({ client->clientSocketfd, true, "ABNORMAL_CLOSURE", WsCloseCode::ABNORMAL_CLOSURE });

            // Log Info (not Error) since its is a expected result for a connection to be closed somehow
            _logger.log(LogLevel::Info, "Handle input: " + std::string(e.what()));
            return false;
        }
    }

    bool coreOutputHandler(const ClientMessage* const message) {
        try {
<<<<<<< bda6237de65624b061d028e5a1626f6ac8125657
<<<<<<< bda6237de65624b061d028e5a1626f6ac8125657
=======
            // The client connection was closed in the meantime, so the message should not be sent
            if(_clientConnections.find(message->clientSocketfd) == _clientConnections.end() || message == nullptr) {
                return false;
            }

>>>>>>> fix recv (split frames)
=======
            // The client connection was closed in the meantime, so the message should not be sent
            if(_clientConnections.find(message->clientSocketfd) == _clientConnections.end() || message == nullptr || message->payloadData.empty()) {
                return false;
            }

>>>>>>> ping pong #1
            // Based on the input message, generate a output message (WebSocket frame)
            auto result = _serverOutputHandler.generateWsDataFrame(_clientConnections[message->clientSocketfd].get(), message);
            if(std::holds_alternative<std::vector<rsByte>>(result)) {
                const std::vector<rsByte>& outputMessage = std::get<std::vector<rsByte>>(result);
                if(_config.outputMethod == OutputMethod::Echo) {
                    // Echo the message back to the client (if it still exists in the clientConnections)
                    auto clientIter = _clientConnections.find(message->clientSocketfd);
                    if(clientIter != _clientConnections.end()) {
                        ssize_t bytesWritten = sendToSocket(message->clientSocketfd, outputMessage);
                        if(bytesWritten < 0) {
                            // throw std::runtime_error("Failed to send message to client: " + clientIter->second->clientAddrStr);
                            // ...
                        }
                    }
                } else if(_config.outputMethod == OutputMethod::Broadcast) {
                    // Broadcast the message to all clients
                    for(auto& client: _clientConnections) {
                        ssize_t bytesWritten = sendToSocket(client.second->clientSocketfd, outputMessage);
                        if(bytesWritten < 0) {
                            // throw std::runtime_error("Failed to send message to client: " + client.second->clientAddrStr);
                            // ...
                        }
                    }
                } else if(_config.outputMethod == OutputMethod::Custom) {
                    // Custom output behavior
                    // ...
                }
                return true;
            } else {
                // Close the connection in case the output handler returned a CloseCondition
                _clientCloseQueue.push(std::get<CloseCondition>(result));
                return false;
            }
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            _clientCloseQueue.push({ message->clientSocketfd, true, "ABNORMAL_CLOSURE", WsCloseCode::ABNORMAL_CLOSURE });

            // Log Info (not Error) since its is a expected result for a connection to be closed somehow
            _logger.log(LogLevel::Info, "Handle output: " + std::string(e.what()));
            return false;
        }
    }

    bool coreConnectionCloseHandler(const CloseCondition& condition) {
        try {
            if(condition.wsConnectionEstablished) {
                // Send a WebSocket close frame to the client
                std::vector<rsByte> closeFrame = _serverOutputHandler.generateWsCloseFrame(static_cast<rsUInt16>(condition.closeCode));
<<<<<<< bda6237de65624b061d028e5a1626f6ac8125657
<<<<<<< bda6237de65624b061d028e5a1626f6ac8125657
                rsInt64 bytesWritten           = send(condition.clientSocketfd, &closeFrame[0], closeFrame.size(), 0);
=======
                rsInt64 bytesWritten           = sendToSocket(condition.clientSocketfd, closeFrame);

>>>>>>> fix recv (split frames)
=======
                rsInt64 bytesWritten           = sendToSocket(condition.clientSocketfd, closeFrame);
>>>>>>> ping pong #1
                if(bytesWritten < 0) {
                    _logger.log(LogLevel::Error, "Failed to send close frame to client: ");
                }
            }

            // Remove the client from the clientConnections, if the client exists there
            if(_clientConnections.find(condition.clientSocketfd) != _clientConnections.end()) {
                _clientConnections.erase(condition.clientSocketfd);
            }

            // Finally: Close the TCP/Socket connection (and remove the client from the epoll instance)
            if(condition.clientSocketfd >= 0) {
                epoll_ctl(_epollfd, EPOLL_CTL_DEL, condition.clientSocketfd, nullptr);
                close(condition.clientSocketfd);
            }

            _logger.log(LogLevel::Info, "Client Connection closed: " + condition.closeInfo);
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "Handle close: " + std::string(e.what()));
            return false;
        }
    }

  private:
    //
    // Send Wrapper
    //
    rsInt64 sendToSocket(int sockfd, const std::vector<rsByte>& data, int flags = 0) noexcept {
        // Check for any socket errors
        int optval;
        socklen_t optlen = sizeof(optval);
        if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) != 0)
            return -1;

        if(optval == 0) {
            // If there are no errors, send the close frame
            rsInt64 bytesSent = send(sockfd, &data[0], data.size(), flags);
            if(bytesSent == -1 && errno == EPIPE) {
                // Handle broken pipe error
                _logger.log(LogLevel::Error, "Broken pipe error: " + std::string(strerror(errno)));
                return -1;
            } else if(bytesSent == -1) {
                // Handle other errors
                _logger.log(LogLevel::Error, "Socket error: " + std::string(strerror(errno)));
                return -1;
            }
            return bytesSent;
        } else {
            _logger.log(LogLevel::Error, "Socket error: " + std::string(strerror(optval)));
            return -1;
        }
    }

  private:
    // Server Config
    int _epollfd;
    int _mainSocketfd;
    const ServerConfig& _config;
    addrinfo* _serverAddrListFull;
    // Server Clients
    std::queue<CloseCondition> _clientCloseQueue;
    std::queue<std::unique_ptr<ClientMessage>> _clientMessageQueue;
    std::unordered_map<int, std::unique_ptr<ClientConnection>> _clientConnections;
    // Server Utility
    const ServerConnectionHandler _serverConnectionHandler;
    const ServerOutputHandler _serverOutputHandler;
    const ServerInputHandler _serverInputHandler;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
