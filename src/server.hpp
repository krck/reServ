#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include "enums.hpp"
#include "logger.hpp"
#include "serverConfig.hpp"
#include "serverConnectionHandler.hpp"
#include "serverMessageHandler.hpp"

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

namespace reServ::Server {

using namespace reServ::Common;

class Server {
  public:
    Server(const ServerConfig& config)
        : _epollfd(-1)
        , _mainSocketfd(-1)
        , _maxBgThreadId(0)
        , _config(config)
        , _serverAddrListFull(nullptr)
        , _clientConnections()
        , _requestQueue()
        , _threadPool()
        , _runBgThreads(true)
        , _serverConnectionHandler(ServerConnectionHandler(config))
        , _logger(Logger::instance()) {
        // Reserve some heap space to reduce memory allocation overhead when new clients are connected
        _clientConnections.reserve(200);
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

            // Start the MAIN EVENT LOOP (that currently can never finish, just crash via exception)
            _logger.log(LogLevel::Info, "Server running: Main Socket listening on port " + std::to_string(_config.port));
            while(true) {
                std::vector<epoll_event> events(_config.maxEpollEvents);
                int numEvents = epoll_wait(_epollfd, &events[0], _config.maxEpollEvents, -1);
                for(int i = 0; i < numEvents; i++) {
                    if(events[i].data.fd == _mainSocketfd) {
                        // New client connection, if the "write" event is on the main listening socket
                        auto newConnection = _serverConnectionHandler.handleNewConnection(_mainSocketfd, _epollfd);
                        if(newConnection.clientSocketfd != -1) {
                            std::lock_guard<std::mutex> lock(_mutex);
                            _clientConnections.insert(std::make_pair(newConnection.clientSocketfd, std::make_unique<Connection>(newConnection)));
                        }
                    } else {
                        // Existing client activity, if the "write" event is on any other (client) socket
                        handleIncomingData(events[i]);
                    }
                }
            }
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "Server: " + std::string(e.what()));
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

        // Check if a socket could be created on any Server address
        if(serverAddr == nullptr || serverSocket < 0) {
            throw std::runtime_error("Failed to create and bind a socket");
        }

        // Set the server socket to non-blocking mode
        // (For edge-triggered epoll, nonblocking sockets MUST be used)
        fcntl(serverSocket, F_SETFL, O_NONBLOCK);

        return serverSocket;
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

            // Log Info (not Error) since its is a expected result for a connection to be closed somehow
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

                    auto message = parseWsMessage(request.second);
                    std::cout << "Message: " << message << std::endl;
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
    const ServerConfig& _config;
    addrinfo* _serverAddrListFull;
    // Server Clients
    std::unordered_map<int, std::unique_ptr<Connection>> _clientConnections;
    std::queue<std::pair<int, std::vector<uint8_t>>> _requestQueue;
    std::unordered_map<int, std::thread> _threadPool;
    std::atomic<bool> _runBgThreads;
    std::condition_variable _cv;
    std::mutex _mutex;
    // Server Utility
    const ServerConnectionHandler _serverConnectionHandler;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
