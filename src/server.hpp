#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>

#include "connection.hpp"
#include "helper.hpp"
#include "logger.hpp"

namespace reServ {

class Server {
public:
    Server(int port) : _port(port), _mainSocketfd(-1), _socketOpt(1), _serverAddrListFull(nullptr), _logger(Logger::instance()) {
        _connectedClients = std::unordered_set<int>();
        // Helper struct for getaddrinfo() which will create the servers address configuration
        // (use AF_UNSPEC to enable IPv4/IPv6 and AI_PASSIVE to automatically fill in the server IP)
        std::memset(&_serverHints, 0, sizeof(_serverHints));
        _serverHints.ai_socktype = SOCK_STREAM;
        _serverHints.ai_family = AF_UNSPEC;
        _serverHints.ai_flags = AI_PASSIVE;
        // Connection backlog: How many con. request will be queued before they get refused
        // (If a connection request arrives when the queue is full, they will get ECONNREFUSED)
        _connectionBacklog = 10;
    }

    bool run() {
        try {
            int addrStatus = 0;
            struct addrinfo* serverAddr;

            // Get the Servers IP address structures, based on the pre-configured "_serverHints" (IPv4/IPv6, auto fill, TCP)
            // (All the Servers IP addresses that match the hint config will be stored in a linked-list struct "_serverAddrList")
            if((addrStatus = getaddrinfo(nullptr, std::to_string(_port).c_str(), &_serverHints, &_serverAddrListFull)) != 0)
                throw std::runtime_error("Failed to get address infos: " + std::string(gai_strerror(addrStatus)));

            // Loop through all the Server IP address results and bind a new socket to the first possible
            for(serverAddr = _serverAddrListFull; serverAddr != nullptr; serverAddr = serverAddr->ai_next) {
                // Create a new socket based on the current serverAddress, wich was configured based on the "_serverHints"
                if((_mainSocketfd = socket(serverAddr->ai_family, serverAddr->ai_socktype, serverAddr->ai_protocol)) < 0) {
                    continue;
                }
                // Attach socket to the defined Port (forcefully - can prevent "Address already in use" errors)
                if(setsockopt(_mainSocketfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &_socketOpt, sizeof(_socketOpt)) < 0) {
                    close(_mainSocketfd);
                    continue;
                }
                // Bind socket to the local IP address and the configured Port/Protocol
                if(bind(_mainSocketfd, serverAddr->ai_addr, serverAddr->ai_addrlen) < 0) {
                    close(_mainSocketfd);
                    continue;
                }
                // In case a socket could be created and bound to a address,
                // stop the loop and use that socket as the main server socket
                break;
            }

            // Check if a socket could be created on any Server address
            if(serverAddr == nullptr || _mainSocketfd < 0) {
                throw std::runtime_error("Failed to create and bind a socket");
            }

            // Put the Server socket in listening mode, waiting to accept new connections
            if(listen(_mainSocketfd, _connectionBacklog) < 0)
                throw std::runtime_error("Failed to initialize listening");

            // Start the CORE SERVER LOOP: Await, accept and handle any new incoming connection
            _logger.log(LogLevel::Info, "Server running. Main Socket listening on port " + std::to_string(_port) + "...");
            while(true) {
                struct sockaddr_storage clientAddr {};
                socklen_t clientAddrSize = sizeof(struct sockaddr_storage);
                // Await a new connection on the main/listening socket ("accept" does the await automatically)
                // In case of a new connection, accept creates a new (client) socket and establishes the connection
                int newClientSocketFd = accept(_mainSocketfd, (struct sockaddr*)&clientAddr, &clientAddrSize);
                if(newClientSocketFd > 0) {
                    // Get the Clients IP Address
                    // (Server-Client connection is now established and data can be transferred)
                    const std::string clientIpStr = extractIpAddrString(&clientAddr);
                    _logger.log(LogLevel::Info, "Client Connection established: " + clientIpStr);

                    // Detach the thread that handles the new Client Connection
                    std::thread tClientConnection{std::thread(&Server::asyncClientConnection, this, newClientSocketFd, clientIpStr)};
                    std::lock_guard<std::mutex> lock(_connectedClientsMutex);
                    _connectedClients.insert(newClientSocketFd);
                    tClientConnection.detach();
                } else {
                    _logger.log(LogLevel::Warning, "Client Connection dropped");
                }
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

        if(_mainSocketfd >= 0) {
            // Close the main/listening socket
            // (Stop any communicaitono with "shutdown" and free the socket descriptor with "close")
            // shutdown(_mainSocketfd, SHUT_RDWR);
            close(_mainSocketfd);
        }
        _logger.log(LogLevel::Info, "Server stopped. Main Socket closed.");
    }

private:
    bool asyncClientConnection(int clientSocketFd, std::string clientIpStr) {
        try {
            // Read client request
            char buffer[1024];
            std::memset(buffer, 0, sizeof(buffer));
            ssize_t bytesRead = recv(clientSocketFd, buffer, sizeof(buffer), 0);
            if(bytesRead > 0) {
                // Parse request and check if it's a WebSocket upgrade request
                const std::string request(buffer);
                if(isWebSocketUpgradeRequest(request)) {
                    auto webSocketConnection = std::make_unique<WebSocketConnection>(clientSocketFd, clientIpStr);
                    webSocketConnection->handleConnection(request);
                } else {
                    auto httpConnection = std::make_unique<HttpConnection>(clientSocketFd, clientIpStr);
                    httpConnection->handleConnection(request);
                }
            } else if(bytesRead == 0) {
                // In case recv returns 0, the connection should be closed (client has closed)
                _logger.log(LogLevel::Info, "Client Connection - requests close: " + clientIpStr);
            } else {
                // In case recv return -1, there was an error and the connection should be closed
                _logger.log(LogLevel::Warning, "Client Connection - unable to read: " + clientIpStr);
            }
            return closeClientSocket(clientSocketFd, clientIpStr);
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "TCP Server: " + std::string(e.what()));
            return closeClientSocket(clientSocketFd, clientIpStr);
        }
    }

    bool closeClientSocket(int socketFd, const std::string& socketClientAddr) {
        // Remove client socket from the set of connected clients
        std::lock_guard<std::mutex> lock(_connectedClientsMutex);
        _connectedClients.erase(socketFd);
        // Close the connection
        if(socketFd >= 0) {
            // Close the client socket
            // (Stop any communicaitono with "shutdown" and free the socket descriptor with "close")
            // shutdown(socketFd, SHUT_RDWR);
            close(socketFd);
        }
        _logger.log(LogLevel::Info, "Client Connection closed: " + socketClientAddr);
        return true;
    }

protected:
    // Server Clients
    std::unordered_set<int> _connectedClients;
    std::mutex _connectedClientsMutex;
    // Server Config
    struct addrinfo* _serverAddrListFull;
    struct addrinfo _serverHints;
    int _connectionBacklog;
    int _mainSocketfd;
    const int _port;
    int _socketOpt;
    // Server Utility
    Logger& _logger;
};

}  // namespace reServ

#endif
