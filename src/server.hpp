#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include "enums.hpp"
#include "helper.hpp"
#include "logger.hpp"
#include "responseMessages.hpp"
#include "wsConfig.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace reServ {

class Server {
  private:
    struct Connection {
      public:
        const int clientSocketfd;
        const sockaddr_storage clientAddr;
        const std::string clientAddrStr;

      public:
        Connection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr)
            : clientSocketfd(clientSocketfd), clientAddr(clientAddr), clientAddrStr(clientAddrStr) {}

        // Delete the copy constructor and copy assignment operator
        Connection(const Connection&)            = delete;
        Connection& operator=(const Connection&) = delete;

        virtual ~Connection() = default;
    };

  public:
    Server(const WsConfig& config)
        : _config(config)
        , _serverAddrListFull(nullptr)
        , _maxBgThreadId(0)
        , _mainSocketfd(-1)
        , _epollfd(-1)
        , _clientConnections()
        , _requestQueue()
        , _threadPool()
        , _runBgThreads(true)
        , _logger(Logger::instance()) {
        // Reserve some heap space to reduce memory allocation overhead when new clients are connected
        _clientConnections.reserve(1000);
        // Initialize the background-thread pool that will process the incoming requests (-1 for main thread)
        const unsigned int numThreads = _maxBgThreadId = (std::thread::hardware_concurrency() - 1);
        for(unsigned int i = 0; i < numThreads; i++) {
            _threadPool[i] = std::thread(&Server::serverBackgroundThread, this, i);
        }
    }

    bool run() {
        try {
            // Create and bind the main server (listening) socket
            if((_mainSocketfd = createAndBindMainServerSocket()) <= 0)
                throw std::runtime_error("Failed to create and bind a socket");

            // Put the Server socket in listening mode, waiting to accept new connections
            // Connection backlog: How many con. request will be queued before they get refused
            // (If a connection request arrives when the queue is full, they will get ECONNREFUSED)
            if(listen(_mainSocketfd, _config.maxConnectionBacklog) < 0)
                throw std::runtime_error("Failed to initialize listening");

            // Create the epoll instance
            if((_epollfd = epoll_create1(0)) <= 0)
                throw std::runtime_error("Failed to create epoll instance");

            // Add the server socket to the epoll instance
            epoll_event event;
            event.events  = EPOLLIN | EPOLLET; // Read events with edge-triggered mode
            event.data.fd = _mainSocketfd;
            epoll_ctl(_epollfd, EPOLL_CTL_ADD, _mainSocketfd, &event);

            // Start the MAIN EVENT LOOP (that currently can never finish, just crash via execption)
            _logger.log(LogLevel::Info, "Server running. Main Socket listening on port " + std::to_string(_config.port) + "...");
            while(true) {
                std::vector<epoll_event> events(_config.maxEpollEvents);
                int numEvents = epoll_wait(_epollfd, &events[0], _config.maxEpollEvents, -1);
                for(int i = 0; i < numEvents; i++) {
                    if(events[i].data.fd == _mainSocketfd) {
                        // New client connection, if the "write" event is on the main listening socket
                        handleNewConnection();
                    } else {
                        // Existing client activity, if the "write" event is on any other (client) socket
                        handleIncomingData(events[i]);
                    }
                }
            }
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "TCP Server: " + std::string(e.what()));
            return false;
        }
    }

    ~Server() {
        // Stop the worker threads and wait for them to finish
        _runBgThreads = false;
        _cv.notify_all();
        for(auto& thread: _threadPool) {
            thread.second.join();
        }

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

    bool handleNewConnection() {
        int newClientSocketFd = -1;
        sockaddr_storage clientAddr {};
        socklen_t clientAddrSize = sizeof(clientAddr);
        try {
            // Accept a new connection on the main/listening socket (creates a new client socket and establishes the connection)
            newClientSocketFd               = accept(_mainSocketfd, (sockaddr*)&clientAddr, &clientAddrSize);
            const std::string clientAddrStr = extractIpAddrString(&clientAddr);
            if(newClientSocketFd < 0)
                return false;

            // Receive initial data from the client
            char recvBuffer[_config.recvBufferSize];
            ssize_t bytesRead = recv(newClientSocketFd, recvBuffer, _config.recvBufferSize, 0);
            const std::string request(recvBuffer, bytesRead);
            if(bytesRead > 0) {
                std::string response;
                if(isWebSocketUpgradeRequest(request)) {
                    // NEW WEBSOCKET CONNECTION (upgrade-request)
                    std::map<std::string, std::string> reqHeaders;
                    const HandshakeValidationCode validationCode = validateWebSocketUpgradeHeader(request, _config.wsVersion, reqHeaders);

                    if(validationCode == HandshakeValidationCode::OK) {
                        // The "Sec-WebSocket-Accept" header must be created and added to the response
                        std::string acceptKey = createWebSocketAcceptKey(reqHeaders["sec-websocket-key"]);
                        response              = getResponse_Handshake_SwitchingProtocols(acceptKey);
                    } else if(validationCode == HandshakeValidationCode::BadRequest) {
                        response = getResponse_Handshake_BadRequest();
                    } else if(validationCode == HandshakeValidationCode::Forbidden) {
                        response = getResponse_Handshake_Forbidden();
                    } else if(validationCode == HandshakeValidationCode::VersionNotSupported) {
                        response = getResponse_UpgradeRequired(_config.wsVersion);
                    }
                } else if(isHttpRequest(request)) {
                    // NEW HTTP CONNECTION (not implemented)
                    std::string res = getResponse_Handshake_NotImplemented();
                }

                // TODO:
                // Check if it makes sense, so setup a "Connection" in case of any other HTTP request
                // (if this Connection is closed immediateley this might not be needed - or is it helpfull for future use-cases?)

                std::lock_guard<std::mutex> lock(_mutex);
                std::unique_ptr<Connection> wsPtr(new Connection(newClientSocketFd, clientAddr, clientAddrStr));
                _clientConnections.insert(std::make_pair(newClientSocketFd, std::move(wsPtr)));

                // If all is fine so far (response generated + client connection saved):
                // then set the client socket to non-blocking mode and add it to the epoll instance
                fcntl(newClientSocketFd, F_SETFL, O_NONBLOCK);
                epoll_event event;
                event.data.fd = newClientSocketFd;
                event.events  = EPOLLIN | EPOLLET; // read events in edge-triggered mode
                epoll_ctl(_epollfd, EPOLL_CTL_ADD, newClientSocketFd, &event);

                ssize_t bytesWritten = send(newClientSocketFd, response.c_str(), response.length(), 0);
                _logger.log(LogLevel::Info, "Client Connection established: " + clientAddrStr);
                return (bytesWritten < 0);
            } else {
                // Close the connection in case recv returned 0, or a WebSocket/HTTP header was not found
                // (control flow via exception since all the cleanup logic is in the catch already)
                throw std::runtime_error("Client Connection closed from remote: " + clientAddrStr);
            }
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "New connection: " + std::string(e.what()));
            // Close the new Socket something went wrong
            if(newClientSocketFd >= 0) {
                close(newClientSocketFd);
                epoll_ctl(_epollfd, EPOLL_CTL_DEL, newClientSocketFd, nullptr);
            }
            // Cleanup all possible remains of the new Socket, depending on where it failed
            if(_clientConnections.find(newClientSocketFd) != _clientConnections.end()) {
                std::lock_guard<std::mutex> lock(_mutex);
                _clientConnections.erase(newClientSocketFd);
            }
            return false;
        }
    }

    void handleIncomingData(const epoll_event& pollEvent) {
        const int clientSockfd = pollEvent.data.fd;
        try {
            // Read data from the client socket
            std::vector<uint8_t> recvBuffer(_config.recvBufferSize);
            ssize_t bytesRead = recv(clientSockfd, &recvBuffer[0], _config.recvBufferSize, 0);
            if(bytesRead > 0) {
                // Add the incoming data to the message queue
                std::lock_guard<std::mutex> lock(_mutex);
                _requestQueue.emplace(clientSockfd, std::move(recvBuffer));
                _cv.notify_one();
            } else {
                // In case recv returns 0, the connection should be closed (client has closed)
                // In case recv return -1, there was an error and the connection should be closed
                // (control flow via exception since all the cleanup logic is in the catch already)
                throw std::runtime_error("Client Connection closed: " + _clientConnections[clientSockfd]->clientAddrStr);
            }
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            // (Remove the client from the epoll instance, the clientConnections and close the socket)
            std::lock_guard<std::mutex> lock(_mutex);
            epoll_ctl(_epollfd, EPOLL_CTL_DEL, clientSockfd, nullptr);
            _clientConnections.erase(clientSockfd);
            close(clientSockfd);

            // Log Info (not Error) since its is a expectd result for a connection to be closed somehow
            _logger.log(LogLevel::Info, "Handle data: " + std::string(e.what()));
        }
    }

    void serverBackgroundThread(const int backgroundThreadId) {
        try {
            while(_runBgThreads) {
                // Background threads are waiting until a "notify_one()" is triggered after a item was added
                std::unique_lock<std::mutex> lock(_mutex);
                _cv.wait(lock, [this]() { return (!_requestQueue.empty() || !_runBgThreads); });
                if(!_runBgThreads)
                    break;

                // Get the added item and unlock the queue again
                auto request = _requestQueue.front();
                _requestQueue.pop();
                lock.unlock();

                // Handle the HTTP or WebSocket client connection async in any of the background threads
                if(_clientConnections.find(request.first) != _clientConnections.end()) {
                    // Handle the request
                    // ... parse incoming data
                    // ... create response
                    // ....

                    size_t index                        = 0;
                    const std::vector<uint8_t>& message = request.second;

                    uint8_t finNopcode  = message[index++];
                    uint8_t maskNlength = message[index++];

                    uint64_t payloadLength = maskNlength & 0x7F;
                    if(payloadLength == 126) {
                        payloadLength = (message[index++] << 8) | message[index++];
                    } else if(payloadLength == 127) {
                        payloadLength = 0;
                        for(int i = 0; i < 8; i++) {
                            payloadLength = (payloadLength << 8) | message[index++];
                        }
                    }

                    std::vector<uint8_t> maskingKey;
                    if(maskNlength & 0x80) {
                        for(int i = 0; i < 4; i++) {
                            maskingKey.push_back(message[index++]);
                        }
                    }

                    std::vector<uint8_t> payloadData(payloadLength);
                    for(uint64_t i = 0; i < payloadLength; i++) {
                        payloadData[i] = message[index++];
                        if(!maskingKey.empty()) {
                            payloadData[i] ^= maskingKey[i % 4];
                        }
                    }

                    const std::string payloadStr(payloadData.begin(), payloadData.end());
                    std::cout << payloadStr << std::endl;
                    // return payloadData;

                    // ...
                }
            }
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "Request Thread: " + std::string(e.what()));

            // Detach and remove this failed background thread
            std::unique_lock<std::mutex> lock(_mutex);
            _threadPool[backgroundThreadId].detach();
            _threadPool.erase(backgroundThreadId);
            // Add a new background thread in its place
            if(_runBgThreads) {
                ++_maxBgThreadId;
                _threadPool[_maxBgThreadId] = std::thread(&Server::serverBackgroundThread, this, _maxBgThreadId);
            }
        }
    }

  private:
    // Server Config
    int _epollfd;
    int _mainSocketfd;
    int _maxBgThreadId;
    const WsConfig& _config;
    addrinfo* _serverAddrListFull;
    // Server Clients
    std::unordered_map<int, std::unique_ptr<Connection>> _clientConnections;
    std::queue<std::pair<int, std::vector<uint8_t>>> _requestQueue;
    std::unordered_map<int, std::thread> _threadPool;
    std::atomic<bool> _runBgThreads;
    std::condition_variable _cv;
    std::mutex _mutex;
    // Server Utility
    Logger& _logger;
};

} // namespace reServ

#endif
