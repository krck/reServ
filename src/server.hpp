#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "connection.hpp"
#include "helper.hpp"
#include "logger.hpp"

namespace reServ {

struct Client {
    int clientSockfd;
    std::string clientAddrStr;
    sockaddr_storage clientAddr;
};

class Server {
public:
    Server(int port, int connectionBacklog = 10, int maxEpollEvents = 100)
        : _port(port), _connectionBacklog(connectionBacklog), _maxEpollEvents(maxEpollEvents), _mainSocketfd(-1), _recvBufferSize(1024),
          _serverAddrListFull(nullptr), _logger(Logger::instance()), _connectedClients(std::unordered_map<int, Client>()) {}

    bool run() {
        try {
            // Create and bind the main server (listening) socket
            if((_mainSocketfd = createAndBindMainServerSocket()) <= 0)
                throw std::runtime_error("Failed to create and bind a socket");

            // Put the Server socket in listening mode, waiting to accept new connections
            // Connection backlog: How many con. request will be queued before they get refused
            // (If a connection request arrives when the queue is full, they will get ECONNREFUSED)
            if(listen(_mainSocketfd, _connectionBacklog) < 0)
                throw std::runtime_error("Failed to initialize listening");

            // Create the epoll instance
            if((_epollfd = epoll_create1(0)) <= 0)
                throw std::runtime_error("Failed to create epoll instance");

            // Add the server socket to the epoll instance
            epoll_event event;
            event.events = EPOLLIN | EPOLLET;  // Read events with edge-triggered mode
            event.data.fd = _mainSocketfd;
            epoll_ctl(_epollfd, EPOLL_CTL_ADD, _mainSocketfd, &event);

            // Start the EVENT LOOP
            _logger.log(LogLevel::Info, "Server running. Main Socket listening on port " + std::to_string(_port) + "...");
            char recvBuffer[_recvBufferSize];
            while(true) {
                epoll_event events[_maxEpollEvents];
                int numEvents = epoll_wait(_epollfd, events, _maxEpollEvents, -1);
                for(int i = 0; i < numEvents; ++i) {
                    // New client connection
                    if(events[i].data.fd == _mainSocketfd) {
                        sockaddr_storage clientAddr{};
                        socklen_t clientAddrSize = sizeof(clientAddr);
                        // Accept a new connection on the main/listening socket
                        // (accept() creates a new client socket and establishes the connection)
                        int newClientSocketFd = accept(_mainSocketfd, (sockaddr*)&clientAddr, &clientAddrSize);
                        if(newClientSocketFd > 0) {
                            // Set the client socket to non-blocking mode
                            fcntl(newClientSocketFd, F_SETFL, O_NONBLOCK);

                            // Add the client socket to the epoll instance
                            event.events = EPOLLIN | EPOLLET;  // Read events with edge-triggered mode
                            event.data.fd = newClientSocketFd;
                            epoll_ctl(_epollfd, EPOLL_CTL_ADD, newClientSocketFd, &event);

                            // Create a new client instance and store it in the clients map
                            // (Server-Client connection is now established and data can be transferred)
                            _connectedClients.insert({newClientSocketFd, {newClientSocketFd, extractIpAddrString(&clientAddr), clientAddr}});
                            _logger.log(LogLevel::Info, "Client Connection established: " + _connectedClients[newClientSocketFd].clientAddrStr);
                        } else {
                            _logger.log(LogLevel::Warning, "Client Connection dropped");
                        }
                    }
                    // Existing client activity
                    else {
                        const int clientSockfd = events[i].data.fd;

                        // Read data from the client socket
                        std::memset(recvBuffer, 0, _recvBufferSize);
                        ssize_t bytesRead = recv(clientSockfd, recvBuffer, _recvBufferSize, 0);
                        if(bytesRead > 0) {
                            std::string receivedData(recvBuffer, bytesRead);
                            // Process the received data (e.g., check for commands, store messages)
                            // ...
                            // if(isWebSocketUpgradeRequest(request)) {
                            //     auto webSocketConnection = std::make_unique<WebSocketConnection>(clientSocketFd, clientIpStr);
                            //     webSocketConnection->handleConnection(request);
                            // } else {
                            //     auto httpConnection = std::make_unique<HttpConnection>(clientSocketFd, clientIpStr);
                            //     httpConnection->handleConnection(request);
                            // }
                            // client.messages.push(receivedData);

                            // Add the client socket to the epoll instance for write events
                            event.events = EPOLLOUT | EPOLLET;  // Write events with edge-triggered mode
                            event.data.fd = clientSockfd;
                            epoll_ctl(_epollfd, EPOLL_CTL_MOD, clientSockfd, &event);
                        } else {
                            // Remove the client from the epoll instance, the clientConnections and close the socket
                            epoll_ctl(_epollfd, EPOLL_CTL_DEL, clientSockfd, nullptr);
                            close(clientSockfd);

                            if(bytesRead == 0) {
                                // In case recv returns 0, the connection should be closed (client has closed)
                                _logger.log(LogLevel::Info, "Client Connection closed (from remote): " + _connectedClients[clientSockfd].clientAddrStr);
                            } else {
                                // In case recv return -1, there was an error and the connection should be closed
                                _logger.log(LogLevel::Warning, "Client Connection closed (error): " + _connectedClients[clientSockfd].clientAddrStr);
                            }

                            _connectedClients.erase(clientSockfd);
                        }
                    }
                }

                // Process pending messages in the message queue
                // while(!messageQueue.empty()) {
                //     std::string message = messageQueue.front();
                //     messageQueue.pop();

                //     // Process the message (e.g., send it to appropriate clients)
                //     // ...
                // }
            }
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "TCP Server: " + std::string(e.what()));
            return false;
        }
    }

    ~Server() {
        // Free the linked list of Server addrinfos
        freeaddrinfo(_serverAddrListFull);

        // Stop any communicaitono with "shutdown" and free the socket descriptor with "close"
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
        int serverSocket = 0;
        int addrStatus = 0;

        // Helper struct for getaddrinfo() which will create the servers address configuration
        std::memset(&serverHints, 0, sizeof(serverHints));
        serverHints.ai_flags = AI_PASSIVE;      // AI_PASSIVE to automatically fill in the server IP
        serverHints.ai_family = AF_UNSPEC;      // AF_UNSPEC to enable IPv4/IPv6
        serverHints.ai_socktype = SOCK_STREAM;  // TCP

        // Get the Servers IP address structures, based on the pre-configured "serverHints" (IPv4/IPv6, auto fill, TCP)
        // (All the Servers IP addresses that match the hint config will be stored in a linked-list struct "_serverAddrList")
        if((addrStatus = getaddrinfo(nullptr, std::to_string(_port).c_str(), &serverHints, &_serverAddrListFull)) != 0)
            throw std::runtime_error("Failed to get address infos: " + std::string(gai_strerror(addrStatus)));

        // Loop through all the Server IP address results and bind a new socket to the first possible
        for(serverAddr = _serverAddrListFull; serverAddr != nullptr; serverAddr = serverAddr->ai_next) {
            // Create a new socket based on the current serverAddress, wich was configured based on the "serverHints"
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

        // Check if a socket could be created on any Server address
        if(serverAddr == nullptr || serverSocket < 0) {
            throw std::runtime_error("Failed to create and bind a socket");
        }

        // Set the server socket to non-blocking mode
        // (For edge-triggered epoll, nonblocking sockets MUST be used)
        fcntl(serverSocket, F_SETFL, O_NONBLOCK);

        return serverSocket;
    }

private:
    // Server Config
    const int _port;
    const int _maxEpollEvents;
    const int _recvBufferSize;
    const int _connectionBacklog;
    addrinfo* _serverAddrListFull;
    int _mainSocketfd;
    int _epollfd;
    // Server Clients
    std::unordered_map<int, Client> _connectedClients;
    // Server Utility
    Logger& _logger;
};

}  // namespace reServ

#endif
