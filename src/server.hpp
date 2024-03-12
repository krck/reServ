#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include "enums.hpp"
#include "logger.hpp"
#include "serverConfig.hpp"
#include "serverConnectionHandler.hpp"
#include "serverInputHandler.hpp"
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

using namespace reServ::Common;

class Server {
  public:
    Server(const ServerConfig& config) :
      _epollfd(-1), _mainSocketfd(-1), _config(config), _serverAddrListFull(nullptr), _clientConnections(), _messageQueue(),
      _serverConnectionHandler(ServerConnectionHandler(config)), _serverInputHandler(ServerInputHandler(config)), _logger(Logger::instance()) {
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
                std::vector<epoll_event> events(_config.maxEpollEvents);
                int numEvents = epoll_wait(_epollfd, &events[0], _config.maxEpollEvents, -1);
                for(int i = 0; i < numEvents; i++) {
                    if(events[i].data.fd == _mainSocketfd) {
                        // New client connection (if the "write" event is on the main listening socket)
                        handleNewConnection();
                    } else if(_clientConnections.find(events[i].data.fd) != _clientConnections.end()) {
                        // Existing client activity (if the "write" event is on any other (client) socket)
                        handleMessageInput(_clientConnections[events[i].data.fd].get());
                    }
                }

                // Handle OUTPUT (send new messages to the clients)
                while(!_messageQueue.empty()) {
                    auto message = _messageQueue.front();
                    _messageQueue.pop();

                    // ...
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
            throw std::runtime_error("Failed to get address infos: " + std::string(gai_strerror(addrStatus)));

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

        if(serverAddr == nullptr || serverSocket < 0) {
            throw std::runtime_error("Failed to create and bind a socket");
        }

        // Set the server socket to non-blocking mode
        // (For edge-triggered epoll, nonblocking sockets MUST be used)
        fcntl(serverSocket, F_SETFL, O_NONBLOCK);

        return serverSocket;
    }

    bool handleNewConnection() {
        int newClientSocketFd = -1;
        sockaddr_storage clientAddr {};
        socklen_t clientAddrSize = sizeof(clientAddr);
        try {
            // Accept a new connection on the main/listening socket (creates a new client socket and establishes the connection)
            newClientSocketFd               = accept(_mainSocketfd, (sockaddr*)&clientAddr, &clientAddrSize);
            const std::string clientAddrStr = extractIpAddrString(&clientAddr);
            if(newClientSocketFd < 0)
                throw std::runtime_error("Failed to accept new client connection: " + clientAddrStr);

            // Receive initial data from the client
            std::vector<rsByte> recvBuffer(_config.recvBufferSize);
            ssize_t bytesRead = recv(newClientSocketFd, &recvBuffer[0], _config.recvBufferSize, 0);
            const std::string request(recvBuffer.begin(), recvBuffer.end());
            if(bytesRead > 0) {
                auto response = _serverConnectionHandler.handleHandshakeRequest(request);

                // Set the client socket to non-blocking mode and add it to the epoll instance
                fcntl(newClientSocketFd, F_SETFL, O_NONBLOCK);
                epoll_event event;
                event.data.fd = newClientSocketFd;
                event.events  = EPOLLIN | EPOLLET; // read events in edge-triggered mode
                epoll_ctl(_epollfd, EPOLL_CTL_ADD, newClientSocketFd, &event);

                // Send the handshake response to the client and save the new client connection
                ssize_t bytesWritten = send(newClientSocketFd, response.c_str(), response.length(), 0);
                if(bytesWritten >= 0) {
                    _logger.log(LogLevel::Info, "Client Connection established: " + clientAddrStr);
                    ClientConnection newConnection { newClientSocketFd, clientAddr, clientAddrStr };
                    _clientConnections.insert({ newClientSocketFd, std::make_unique<ClientConnection>(newConnection) });
                    return true;
                } else {
                    throw std::runtime_error("Failed to send handshake response to client: " + clientAddrStr);
                }
            } else {
                // Close the connection in case recv returned 0, or a WebSocket/HTTP header was not found
                // (control flow via exception since all the cleanup logic is in the catch already)
                throw std::runtime_error("Client Connection closed from remote: " + clientAddrStr);
            }
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "ConnectionHandler: " + std::string(e.what()));
            if(newClientSocketFd >= 0) {
                close(newClientSocketFd);
                epoll_ctl(_epollfd, EPOLL_CTL_DEL, newClientSocketFd, nullptr);
            }
            return false;
        }
    }

    bool handleMessageInput(const ClientConnection* const client) {
        try {
            // Read incoming data from the client socket
            std::vector<rsByte> recvBuffer(_config.recvBufferSize);
            ssize_t bytesRead = recv(client->clientSocketfd, &recvBuffer[0], _config.recvBufferSize, 0);
            if(bytesRead > 0) {
                auto message = _serverInputHandler.handleInputData(client->clientSocketfd, recvBuffer);
                _messageQueue.push({ client->clientSocketfd, message });
                _logger.log(LogLevel::Info, "Received message: " + message);
                return true;
            } else {
                // In case recv returns 0, the connection should be closed (client has closed)
                // In case recv return -1, there was an error and the connection should be closed
                // (control flow via exception since all the cleanup logic is in the catch already)
                throw std::runtime_error("Client Connection closed: " + client->clientAddrStr);
            }
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            // (Remove the client from the epoll instance, the clientConnections and close the socket)
            epoll_ctl(_epollfd, EPOLL_CTL_DEL, client->clientSocketfd, nullptr);
            _clientConnections.erase(client->clientSocketfd);
            close(client->clientSocketfd);

            // Log Info (not Error) since its is a expected result for a connection to be closed somehow
            _logger.log(LogLevel::Info, "Handle data: " + std::string(e.what()));
            return false;
        }
    }

    //
    // Return a IPv4/IPv6 address as a (readable) string
    //
    std::string extractIpAddrString(sockaddr_storage* addr) const {
        if(addr->ss_family == AF_INET) {
            // IP v4 Address
            struct sockaddr_in* addr_v4 = (struct sockaddr_in*)addr;
            return std::string(inet_ntoa(addr_v4->sin_addr));
        } else {
            // IP v6 Address
            char a[INET6_ADDRSTRLEN] { '\0' };
            struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)addr;
            inet_ntop(AF_INET6, &(addr_v6->sin6_addr), a, INET6_ADDRSTRLEN);
            return std::string(a);
        }
    }

  private:
    // Server Config
    int _epollfd;
    int _mainSocketfd;
    const ServerConfig& _config;
    addrinfo* _serverAddrListFull;
    // Server Clients
    std::unordered_map<int, std::unique_ptr<ClientConnection>> _clientConnections;
    std::queue<std::pair<int, std::string>> _messageQueue;
    // Server Utility
    const ServerConnectionHandler _serverConnectionHandler;
    const ServerInputHandler _serverInputHandler;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
