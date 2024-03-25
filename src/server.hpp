#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include "clientConnection.hpp"
#include "configService.hpp"
#include "enums.hpp"
#include "logger.hpp"
#include "serverConnectionHandler.hpp"
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
#include <variant>

namespace reServ::Server {

using namespace reServ::Client;
using namespace reServ::Common;

class Server {
  public:
    Server() :
      _epollfd(-1), _mainSocketfd(-1), _config(ConfigService::instance().getServerConfig()), _serverAddrListFull(nullptr), _clientMessageQueue(),
      _messageSegmentationBuffer(), _clientConnections(), _serverConnectionHandler(ServerConnectionHandler()),
      _serverOutputHandler(ServerOutputHandler()), _logger(Logger::instance()) {
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
            if((_epollfd = epoll_create1(0)) < 0)
                throw std::runtime_error("Failed to create epoll instance");

            epoll_event mainCtlEvent {};
            mainCtlEvent.data.fd = _mainSocketfd;
            mainCtlEvent.events  = EPOLLIN | EPOLLET;
            if(epoll_ctl(_epollfd, EPOLL_CTL_ADD, _mainSocketfd, &mainCtlEvent) < 0)
                throw std::runtime_error("Failed to add main socket to epoll instance");

            // -------------------------------------------------------------------------------------
            // Start the MAIN EVENT LOOP (that currently can never finish, just crash via exception)
            // -------------------------------------------------------------------------------------
            _logger.log(LogLevel::Info, "Server running: Main Socket listening on port " + std::to_string(_config.port));
            std::vector<epoll_event> events(_config.maxEpollEvents);
            while(true) {
                int numEvents = epoll_wait(_epollfd, &events[0], _config.maxEpollEvents, -1);
                if(numEvents == -1)
                    break;

                // 1. Handle INPUT (new client connections and existing client activity)
                for(int i = 0; i < numEvents; i++) {
                    if((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
                        // Error case on the "write" event
                        continue;
                    } else if(events[i].data.fd == _mainSocketfd) {
                        // New client connection (if the "write" event is on the main listening socket)
                        coreConnectionCreateHandler();
                    } else if(_clientConnections.find(events[i].data.fd) != _clientConnections.end()) {
                        // Existing client activity (if the "write" event is on any other (client) socket)
                        coreInputHandler(_clientConnections[events[i].data.fd].get());
                    }
                }

                // 2. Handle OUTPUT (send new messages to the clients)
                while(!_clientMessageQueue.empty()) {
                    Message* message = _clientMessageQueue.front().get();
                    coreOutputHandler(message);
                    _clientMessageQueue.pop();
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
    rsSocketFd createAndBindMainServerSocket() {
        addrinfo* serverAddr;
        addrinfo serverHints;
        rsSocketFd serverSocket = 0;
        int socketOptions       = 0;
        int addrStatus          = 0;

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
        if(fcntl(serverSocket, F_SETFL, O_NONBLOCK) < 0) {
            return -1;
        }

        return serverSocket;
    }

    bool coreConnectionCreateHandler() {
        try {
            // Accept all new connections on the main/listening socket
            // (creates a new client socket and establishes the connection)
            while(true) {
                rsSocketFd newClientSocketFd = -1;
                sockaddr_storage clientAddr  = {};
                socklen_t clientAddrSize     = sizeof(clientAddr);

                newClientSocketFd = accept(_mainSocketfd, (sockaddr*)&clientAddr, &clientAddrSize);
                if(newClientSocketFd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    // No more new connections to accept on the main socket
                    break;
                } else if(newClientSocketFd >= 0) {
                    // Extract the client IP address as readable string
                    std::string clientAddrStr;
                    if(clientAddr.ss_family == AF_INET) {
                        // IP v4 Address
                        struct sockaddr_in* addr_v4 = (struct sockaddr_in*)&clientAddr;
                        clientAddrStr               = std::string(inet_ntoa(addr_v4->sin_addr));
                    } else {
                        // IP v6 Address
                        char a[INET6_ADDRSTRLEN] { '\0' };
                        struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)&clientAddr;
                        inet_ntop(AF_INET6, &(addr_v6->sin6_addr), a, INET6_ADDRSTRLEN);
                        clientAddrStr = std::string(a);
                    }
                    if(clientAddrStr.empty()) {
                        _logger.log(LogLevel::Error, "Failed to extract client IP address");
                        continue;
                    }

                    // Set the client socket to non-blocking mode
                    if(fcntl(newClientSocketFd, F_SETFL, O_NONBLOCK) < 0) {
                        _logger.log(LogLevel::Error, ("Failed to set new client socket to non-blocking mode: " + clientAddrStr));
                        continue;
                    }

                    // Add the new client socket to the epoll instance
                    epoll_event epollEvent {};
                    epollEvent.data.fd = newClientSocketFd;
                    epollEvent.events  = EPOLLIN | EPOLLET; // read events in edge-triggered mode
                    if(epoll_ctl(_epollfd, EPOLL_CTL_ADD, newClientSocketFd, &epollEvent) < 0) {
                        _logger.log(LogLevel::Error, ("Failed to add new client to epoll instance: " + clientAddrStr));
                        continue;
                    }

                    auto newConnection = std::make_unique<ClientConnection>(newClientSocketFd, _epollfd, clientAddrStr, clientAddr, epollEvent);
                    if(newConnection->getState() == ClientWebSocketState::Created) {
                        _logger.log(LogLevel::Debug, ("New client connection created: " + clientAddrStr));
                        _clientConnections.insert({ newClientSocketFd, std::move(newConnection) });
                    }
                    // If the connection was not setup properly and moved to _clientConnections
                    // it will be automatically closed and deleted here (no close frame needed)
                } else {
                    _logger.log(LogLevel::Error, "Failed to accept new client connection");
                    continue;
                }
            }
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "Handle connection: " + std::string(e.what()));
            return false;
        }
    }

    bool coreInputHandler(ClientConnection* const client) {
        try {
            std::vector<rsByte> recvBuf;
            auto result = recvFromSocket(client->clientSocketfd, recvBuf);

            // In case of "recv" Error: Send a WebSocket close frame back to the client
            if(result.bytesRecv == 0 || result.state == SocketState::ConnectionClose) {
                auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::NORMAL_CLOSURE);
                auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                _clientMessageQueue.push(std::move(message));
                client->setClosing();
                return false;
            } else if(result.state == SocketState::MaxLengthExceeded) {
                auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::MESSAGE_TOO_BIG);
                auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                _clientMessageQueue.push(std::move(message));
                client->setClosing();
                return false;
            } else if(result.state == SocketState::ConnectionReset || result.state == SocketState::Undefined) {
                auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::ABNORMAL_CLOSURE);
                auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                _clientMessageQueue.push(std::move(message));
                client->setClosing();
                return false;
            }

            if(client->getState() == ClientWebSocketState::Created) {
                // On a newly created connection the first message received MUST be a HTTP WebSocket upgrade request
                auto httpResponse = _serverConnectionHandler.handleHandshakeRequest(std::string(recvBuf.begin(), recvBuf.end()));
                std::vector<rsByte> responseBytes(httpResponse.begin(), httpResponse.end());

                auto message = std::make_unique<Message>(client->clientSocketfd, responseBytes.size(), OutputMethod::Echo, responseBytes);
                _clientMessageQueue.push(std::move(message));
                client->setHandshakeStarted();
            } else if(client->getState() == ClientWebSocketState::Open) {
                // ---------------------------------------------- CREATE NEW MESSAGE -----------------------------------------------
                // -- If no uncompleted segment exists, then this is the beginning of a new message and the header must be parsed --
                // -----------------------------------------------------------------------------------------------------------------
                rsUInt64 headerFrameSize = 0;
                const rsUInt64 bytesRecv = result.bytesRecv;
                if(_messageSegmentationBuffer.find(client->clientSocketfd) == _messageSegmentationBuffer.end()) {
                    // Validate if we have a complete WebSocket frame
                    // (must be at least two bytes for a basic header)
                    if(bytesRecv < 2) {
                        auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::PROTOCOL_ERROR);
                        auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                        _clientMessageQueue.push(std::move(message));
                        client->setClosing();
                        return false;
                    }

                    // The first BYTE contains the FIN bit, RSV1, RSV2, RSV3, and the OP-Code
                    // |7|6|5|4|3|2|1|0|
                    // |F|R|R|R| opcode|
                    const WsFrame_FIN fin = static_cast<WsFrame_FIN>(recvBuf[0] & 0x80); // 0b10000000
                    const WsFrame_RSV rsv = static_cast<WsFrame_RSV>(recvBuf[0] & 0x70); // 0b01110000
                    const WsFrame_OPC opc = static_cast<WsFrame_OPC>(recvBuf[0] & 0x0F); // 0b00001111

                    // The second BYTE contains the MASK bit and the payload length
                    // |7|6|5|4|3|2|1|0|
                    // |M| Payload len |
                    const bool maskBitSet     = static_cast<bool>(recvBuf[1] & 0x80);     // 0b10000000
                    rsUInt64 tmpPayloadLength = static_cast<rsUInt64>(recvBuf[1] & 0x7F); // 0b01111111
                    if(!maskBitSet) {
                        // The server MUST close the connection upon receiving a frame with the mask bit set to 0
                        // (The client MUST always set the mask bit to 1, as defined in the RFC)
                        auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::PROTOCOL_ERROR);
                        auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                        _clientMessageQueue.push(std::move(message));
                        client->setClosing();
                        return false;
                    }

                    // Validate further: Header must have enough bytes for the extended payload length
                    if((tmpPayloadLength == 126 && (bytesRecv < 4)) || (tmpPayloadLength == 127 && (bytesRecv < 10))) {
                        auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::PROTOCOL_ERROR);
                        auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                        _clientMessageQueue.push(std::move(message));
                        client->setClosing();
                        return false;
                    }

                    // Use the temporary payload length to determine how many of the bytes to use:
                    // - If the value is between 0-125, the 7 bits in the second byte represent the actual payload length
                    // - If the value is 126, the payload length is determined by the following 2 bytes interpreted as a 16-bit unsigned integer
                    // - If the value is 127, the payload length is determined by the following 8 bytes interpreted as a 64-bit unsigned integer
                    // (The most significant bit must be 0. in all cases, the minimal number of bytes must be used to encode the length)
                    headerFrameSize              = 2;
                    rsUInt64 actualPayloadLength = 0;
                    if(tmpPayloadLength == 126) {
                        // Bytes 3-4 are used if payloadLength == 126
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                    } else if(tmpPayloadLength == 127) {
                        // Bytes 3-10 are used if payloadLength == 127
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                        actualPayloadLength = (actualPayloadLength << 8) | recvBuf[headerFrameSize++];
                    } else {
                        actualPayloadLength = tmpPayloadLength;
                    }

                    // Validate further: Header must have enough bytes for the Masking-Key (MUST be set from Client)
                    if(bytesRecv < (headerFrameSize + 4UL)) {
                        auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::PROTOCOL_ERROR);
                        auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                        _clientMessageQueue.push(std::move(message));
                        client->setClosing();
                        return false;
                    }

                    // Read the Masking-Key
                    // The masking key is a 32-bit value, spanning the next 4 bytes after the payload length
                    // (In theory only done if the mask bit is set, but the Client MUST always mask ALL frames, as defined in the RFC)
                    rsUInt32 maskingKey = 0;
                    maskingKey          = (maskingKey << 8) | recvBuf[headerFrameSize++];
                    maskingKey          = (maskingKey << 8) | recvBuf[headerFrameSize++];
                    maskingKey          = (maskingKey << 8) | recvBuf[headerFrameSize++];
                    maskingKey          = (maskingKey << 8) | recvBuf[headerFrameSize++];

                    // At this point, the header is fully parsed and validated
                    // (this means the message object can be created for the client)
                    auto message = std::make_unique<WebSocketMessage>(client->clientSocketfd, fin, rsv, opc, maskingKey, actualPayloadLength,
                                                                      _config.outputMethod);
                    _messageSegmentationBuffer.insert({ client->clientSocketfd, std::move(message) });
                }

                // --------------------------------------- APPEND SEGMENT DATA TO THE MESSAGE --------------------------------------
                // -- Get the message segment for this client and append the received data. Then check if the message is complete --
                // -----------------------------------------------------------------------------------------------------------------
                auto* message = dynamic_cast<WebSocketMessage*>(_messageSegmentationBuffer[client->clientSocketfd].get());
                // Read the Payload Data
                // (In theory divided into "Extension Data" and "Application Data", but extention must be specifically negotiated)
                const rsUInt64 framePayloadSize = (bytesRecv - headerFrameSize);
                const rsUInt32 maskingKey       = message->maskingKey;
                std::vector<rsByte> payloadData(framePayloadSize);
                for(rsUInt64 i = 0; i < framePayloadSize; i++) {
                    // For each byte in the payload, perform an XOR operation with the corresponding byte from the masking key
                    // The masking key is treated as a circular array, hence the use of 'i % 4' to select the next appropriate byte
                    payloadData[i] = (recvBuf[headerFrameSize++] ^ ((maskingKey >> (8 * (3 - i % 4))) & 0xFF));
                }
                message->appendPayload(payloadData);

                _logger.log(LogLevel::Debug, "Received message segment: " + std::to_string(bytesRecv) + " pl:" + std::to_string(framePayloadSize));
                //_logger.log(LogLevel::Debug, "Received message: " + std::string(payloadData.begin(), payloadData.end()));

                // Check if the message is complete and can be processed
                if(message->isReceived()) {
                    _clientMessageQueue.push(std::move(_messageSegmentationBuffer[client->clientSocketfd]));
                    _messageSegmentationBuffer.erase(client->clientSocketfd);
                }

                return true;
            }
            return false;
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::ABNORMAL_CLOSURE);
            auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
            _clientMessageQueue.push(std::move(message));

            _messageSegmentationBuffer.erase(client->clientSocketfd);
            client->setClosing();

            _logger.log(LogLevel::Error, "Handle input: " + std::string(e.what()));
            return false;
        }
    }

    bool coreOutputHandler(const Message* const message) {
        // The client connection was closed in the meantime, so the message should not be sent
        if(_clientConnections.find(message->clientSocketfd) == _clientConnections.end() || message == nullptr) {
            return false;
        }

        auto& client = _clientConnections[message->clientSocketfd];
        try {
            if(client->getState() == ClientWebSocketState::Handshake) {
                // If its still the Handshake: Just send the "raw" bytes, no frame/header
                // (and always just send it as an Echo back to the client)
                const auto result = sendToSocket(message->clientSocketfd, message->getPayload());
                if(result.state != SocketState::OK) {
                    _logger.log(LogLevel::Debug, "Failed to send message to client: " + client->clientAddrStr);
                    auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::PROTOCOL_ERROR);
                    auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                    _clientMessageQueue.push(std::move(message));
                    client->setClosing();
                    return false;
                } else {
                    _logger.log(LogLevel::Debug, "Handshake message sent: " + client->clientAddrStr);
                    client->setHandshakeCompleted();
                    return true;
                }
            } else {
                // The connection is open or closing: Send the message as a WebSocket frame
                // (Based on the input message, generate a output message)
                auto result = _serverOutputHandler.generateWsDataFrame(_clientConnections[message->clientSocketfd].get(),
                                                                       dynamic_cast<const WebSocketMessage* const>(message));
                if(std::holds_alternative<std::vector<rsByte>>(result)) {
                    const std::vector<rsByte>& outputMessage = std::get<std::vector<rsByte>>(result);
                    if(message->outputMethod == OutputMethod::Echo) {
                        // Echo the message back to the client (if it still exists in the clientConnections)
                        auto clientIter = _clientConnections.find(message->clientSocketfd);
                        if(clientIter != _clientConnections.end()) {
                            const auto result = sendToSocket(message->clientSocketfd, outputMessage);
                            _logger.log(LogLevel::Debug, "Echo message sent: " + std::to_string(result.bytesSent));
                            if(result.state != SocketState::OK) {
                                // throw std::runtime_error("Failed to send message to client: " + clientIter->second->clientAddrStr);
                                // ...
                            }
                        }
                    } else if(message->outputMethod == OutputMethod::Broadcast) {
                        // Broadcast the message to all clients
                        for(auto& client: _clientConnections) {
                            const auto result = sendToSocket(client.second->clientSocketfd, outputMessage);
                            _logger.log(LogLevel::Debug, "Broadcast message sent: " + std::to_string(result.bytesSent));
                            if(result.state != SocketState::OK) {
                                // throw std::runtime_error("Failed to send message to client: " + client.second->clientAddrStr);
                                // ...
                            }
                        }
                    } else if(message->outputMethod == OutputMethod::Custom) {
                        // Custom output behavior
                        // ...
                    }
                    return true;
                } else {
                    // Close the connection in case the output handler returned a WsCloseCode
                    auto closeFrame = _serverOutputHandler.generateWsCloseFrame(std::get<WsCloseCode>(result));
                    auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                    _clientMessageQueue.push(std::move(message));
                    client->setClosing();
                    return false;
                }
            }
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            auto closeFrame = _serverOutputHandler.generateWsCloseFrame(WsCloseCode::ABNORMAL_CLOSURE);
            auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
            _clientMessageQueue.push(std::move(message));
            client->setClosing();

            _logger.log(LogLevel::Error, "Handle output: " + std::string(e.what()));
            return false;
        }
    }

  private:
    //
    // Send Wrapper
    //
    struct SendResult {
        const rsUInt64 bytesSent;
        const SocketState state;
    };
    SendResult sendToSocket(rsSocketFd clientSocketfd, const std::vector<rsByte>& sendBuf, int flags = 0) noexcept {
        rsUInt64 totalBytesSent = 0;
        while(totalBytesSent < sendBuf.size()) {
            //  Call send with MSG_NOSIGNAL to prevent the send function from raising a SIGPIPE signal
            // (instead it will return -1 and set errno to EPIPE if the connection is broken)
            rsInt64 bytesSent = send(clientSocketfd, &sendBuf[totalBytesSent], sendBuf.size() - totalBytesSent, flags | MSG_NOSIGNAL);
            if(bytesSent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // No more data to write on the client socket
                break;
            } else if(bytesSent == -1 && errno == EPIPE) {
                // Handle broken pipe error
                _logger.log(LogLevel::Error, "Broken pipe error: " + std::string(strerror(errno)));
                return { totalBytesSent, SocketState::BrokenPipe };
            } else if(bytesSent == -1) {
                // Handle other errors
                _logger.log(LogLevel::Error, "Socket error: " + std::string(strerror(errno)));
                return { totalBytesSent, SocketState::Undefined };
            }
            totalBytesSent += bytesSent;
        }
        return { totalBytesSent, SocketState::OK };
    }

    //
    // Recv Wrapper
    //
    struct RecvResult {
        const rsUInt64 bytesRecv;
        const SocketState state;
    };
    RecvResult recvFromSocket(rsSocketFd clientSocketfd, std::vector<rsByte>& recvBuf, int flags = 0) noexcept {
        rsUInt64 totalBytesRecv = 0;
        rsInt64 bytesRecv       = 0;

        // Clear and resize the buffer (swap-and-clear)
        std::vector<rsByte>(_config.recvBufferSize).swap(recvBuf);
        const int rFlags = (flags | MSG_DONTWAIT | MSG_NOSIGNAL);

        // Receive incoming data, until there is no more data to read on the client socket
        while((bytesRecv = recv(clientSocketfd, &recvBuf[totalBytesRecv], recvBuf.size() - totalBytesRecv, rFlags)) > 0) {
            if(bytesRecv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // No more data to read on the client socket
                break;
            } else if(bytesRecv == -1 && errno == ECONNRESET) {
                // Handle connection reset by peer
                _logger.log(LogLevel::Error, "Connection reset by peer: " + std::string(strerror(errno)));
                return { totalBytesRecv, SocketState::ConnectionReset };
            } else if(bytesRecv == -1) {
                // Handle other errors
                _logger.log(LogLevel::Error, "Socket error: " + std::string(strerror(errno)));
                return { totalBytesRecv, SocketState::Undefined };
            } else if(bytesRecv == 0) {
                // Handle connection closed by client
                _logger.log(LogLevel::Info, "Connection closed by client: " + std::string(strerror(errno)));
                return { totalBytesRecv, SocketState::ConnectionClose };
            }

            totalBytesRecv += bytesRecv;

            // Resize the buffer if its full (scale by always doubling the size to reduce allocation overhead)
            if(totalBytesRecv == recvBuf.size()) {
                // Check for buffer overflow (if buffer is too large, close the connection)
                if(recvBuf.size() * 2 > (rsUInt64)(_config.maxPayloadLength + _config.frameHeaderSize)) {
                    _logger.log(LogLevel::Error, "Max length exceeded: " + std::to_string(totalBytesRecv));
                    return { totalBytesRecv, SocketState::MaxLengthExceeded };
                }
                recvBuf.resize(recvBuf.size() * 2);
            }
        }

        return { totalBytesRecv, SocketState::OK };
    }

  private:
    // Server Config
    rsSocketFd _epollfd;
    rsSocketFd _mainSocketfd;
    const ServerConfig& _config;
    addrinfo* _serverAddrListFull;
    // Server Clients
    std::queue<std::unique_ptr<Message>> _clientMessageQueue;
    std::unordered_map<int, std::unique_ptr<Message>> _messageSegmentationBuffer;
    std::unordered_map<int, std::unique_ptr<ClientConnection>> _clientConnections;
    // Server Utility
    const ServerConnectionHandler _serverConnectionHandler;
    const ServerOutputHandler _serverOutputHandler;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
