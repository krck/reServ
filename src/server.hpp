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

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

#include "connection.hpp"
#include "helper.hpp"
#include "logger.hpp"

namespace reServ {

#define RECV_BUFF_SIZE 1024

class Server {
public:
    Server(int port, int connectionBacklog = 10, int maxEpollEvents = 100)
        : _port(port), _maxEpollEvents(maxEpollEvents), _connectionBacklog(connectionBacklog), _serverAddrListFull(nullptr),
          _mainSocketfd(-1), _epollfd(-1), _clientConnections(), _requestQueue(), _threadPool(), _runBgTasks(true), _logger(Logger::instance()) {
        // Reserve some heap space to reduce memory allocation overhead when new clients are connected
        _clientConnections.reserve(1000);
        // Initialize the background-thread pool that will process the incoming requests (-1 for main thread)
        const unsigned int numThreads = (std::thread::hardware_concurrency() - 1);
        for(unsigned int i = 0; i < numThreads; i++) {
            _threadPool.emplace_back([this]() { requestBackgroundTask(); });
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

            // Start the MAIN EVENT LOOP (that currently can never finish, just crash via execption)
            _logger.log(LogLevel::Info, "Server running. Main Socket listening on port " + std::to_string(_port) + "...");
            while(true) {
                std::vector<epoll_event> events(_maxEpollEvents);
                int numEvents = epoll_wait(_epollfd, &events[0], _maxEpollEvents, -1);
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
        _runBgTasks = false;
        _cv.notify_all();
        for(auto& thread : _threadPool) {
            thread.join();
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

    bool handleNewConnection() {
        sockaddr_storage clientAddr{};
        socklen_t clientAddrSize = sizeof(clientAddr);
        // Accept a new connection on the main/listening socket (creates a new client socket and establishes the connection)
        int newClientSocketFd = accept(_mainSocketfd, (sockaddr*)&clientAddr, &clientAddrSize);
        const std::string clientAddrStr = extractIpAddrString(&clientAddr);
        if(newClientSocketFd < 0)
            return false;

        // Receive initial data from the client
        char recvBuffer[RECV_BUFF_SIZE];
        ssize_t bytesRead = recv(newClientSocketFd, recvBuffer, RECV_BUFF_SIZE, 0);
        const std::string recvDataStr(recvBuffer, bytesRead);
        if(bytesRead > 0) {
            // 1. WEBSOCKET CONNECTION
            //    Check if the initial data sent from the Client contains the "upgrade: websocket" header
            if(isWebSocketUpgradeRequest(recvDataStr)) {
                std::lock_guard<std::mutex> lock(_mutex);
                std::unique_ptr<Connection> wsPtr(new WebSocketConnection(newClientSocketFd, clientAddr, clientAddrStr));
                _clientConnections.insert(std::make_pair(newClientSocketFd, std::move(wsPtr)));
            }
            // 2. HTTP CONNECTION
            //    Check if the initial data sent from the Client contains a known HTTP Method
            else if(isHttpRequest(recvDataStr)) {
                std::lock_guard<std::mutex> lock(_mutex);
                std::unique_ptr<Connection> httpPtr(new HttpConnection(newClientSocketFd, clientAddr, clientAddrStr));
                _clientConnections.insert(std::make_pair(newClientSocketFd, std::move(httpPtr)));
            }
        }

        // Check if a Connection (WebSocket or HTTP) was established and saved
        if(_clientConnections.find(newClientSocketFd) != _clientConnections.end()) {
            // Set the client socket to non-blocking mode and add it to the epoll instance
            fcntl(newClientSocketFd, F_SETFL, O_NONBLOCK);
            epoll_event event;
            event.data.fd = newClientSocketFd;
            event.events = EPOLLIN | EPOLLET;  // read events in edge-triggered mode
            epoll_ctl(_epollfd, EPOLL_CTL_ADD, newClientSocketFd, &event);

            // Once the Client connection is established and the socket is configured:
            // Handle the "initial" incoming message like any other message (background threads)
            std::lock_guard<std::mutex> lock(_mutex);
            _requestQueue.emplace(newClientSocketFd, recvDataStr);
            _cv.notify_one();

            _logger.log(LogLevel::Info, "Client Connection established: " + clientAddrStr);
            return true;
        }
        // Close the connection in case recv returned 0, or a WebSocket/HTTP header was not found
        else {
            close(newClientSocketFd);
            _logger.log(LogLevel::Info, "Client Connection closed (from remote): " + clientAddrStr);
            return false;
        }
    }

    void handleIncomingData(const epoll_event& pollEvent) {
        const int clientSockfd = pollEvent.data.fd;

        // Read data from the client socket
        char recvBuffer[RECV_BUFF_SIZE];
        ssize_t bytesRead = recv(clientSockfd, recvBuffer, RECV_BUFF_SIZE, 0);
        if(bytesRead > 0) {
            // Add the incoming data to the message queue
            std::lock_guard<std::mutex> lock(_mutex);
            _requestQueue.emplace(clientSockfd, std::string(recvBuffer, bytesRead));
            _cv.notify_one();
        } else {
            // Close the connection in case recv returned 0
            // (Remove the client from the epoll instance, the clientConnections and close the socket)
            std::lock_guard<std::mutex> lock(_mutex);
            const std::string clientAddrStr = _clientConnections[clientSockfd]->getAddress();
            epoll_ctl(_epollfd, EPOLL_CTL_DEL, clientSockfd, nullptr);
            _clientConnections.erase(clientSockfd);
            close(clientSockfd);

            if(bytesRead == 0) {
                // In case recv returns 0, the connection should be closed (client has closed)
                _logger.log(LogLevel::Info, "Client Connection closed (from remote): " + clientAddrStr);
            } else {
                // In case recv return -1, there was an error and the connection should be closed
                _logger.log(LogLevel::Warning, "Client Connection closed (error): " + clientAddrStr);
            }
        }
    }

    void requestBackgroundTask() {
        while(_runBgTasks) {
            // Background threads are waiting until a "notify_one()" is triggered after a item was added
            std::unique_lock<std::mutex> lock(_mutex);
            _cv.wait(lock, [this]() { return (!_requestQueue.empty() || !_runBgTasks); });
            if(!_runBgTasks)
                break;

            // Get the added item and unlock the queue again
            auto request = _requestQueue.front();
            _requestQueue.pop();
            lock.unlock();

            // Handle the HTTP or WebSocket client connection async in any of the background threads
            int clientSockfd = request.first;
            if(_clientConnections.find(clientSockfd) != _clientConnections.end())
                _clientConnections[clientSockfd]->handleRequest(request.second);
        }
    }

private:
    // Server Config
    const int _port;
    const int _maxEpollEvents;
    const int _connectionBacklog;
    addrinfo* _serverAddrListFull;
    int _mainSocketfd;
    int _epollfd;
    // Server Clients
    std::unordered_map<int, std::unique_ptr<Connection>> _clientConnections;
    std::queue<std::pair<int, std::string>> _requestQueue;
    std::vector<std::thread> _threadPool;
    std::atomic<bool> _runBgTasks;
    std::condition_variable _cv;
    std::mutex _mutex;
    // Server Utility
    Logger& _logger;
};

}  // namespace reServ

#endif
