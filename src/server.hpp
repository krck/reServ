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
            // -------------------------------------------------------------------------------
            // ---------------------- INITIALIZE THE MAIN SERVER SOCKET ----------------------
            // -------------------------------------------------------------------------------
            {
                addrinfo* serverAddr;
                addrinfo serverHints;
                int socketOptions = 0;
                int addrStatus    = 0;

                // Helper struct for getaddrinfo() which will create the servers address configuration
                std::memset(&serverHints, 0, sizeof(serverHints));
                serverHints.ai_flags    = AI_PASSIVE;  // AI_PASSIVE to automatically fill in the server IP
                serverHints.ai_family   = AF_UNSPEC;   // AF_UNSPEC to enable IPv4/IPv6
                serverHints.ai_socktype = SOCK_STREAM; // TCP

                // Get the Servers IP address structures, based on the pre-configured "serverHints" (IPv4/IPv6, auto fill, TCP)
                // (All the Servers IP addresses that match the hint config will be stored in a linked-list struct "_serverAddrList")
                if((addrStatus = getaddrinfo(nullptr, std::to_string(_config.port).c_str(), &serverHints, &_serverAddrListFull)) != 0)
                    throw std::runtime_error("Init: Failed to get system address structures");

                // Loop through all the Server IP address results and bind a new socket to the first possible
                for(serverAddr = _serverAddrListFull; serverAddr != nullptr; serverAddr = serverAddr->ai_next) {
                    // Create a new socket based on the current serverAddress, which was configured based on the "serverHints"
                    if((_mainSocketfd = socket(serverAddr->ai_family, serverAddr->ai_socktype, serverAddr->ai_protocol)) < 0) {
                        continue;
                    }
                    // Attach socket to the defined Port (forcefully - can prevent "Address already in use" errors)
                    if(setsockopt(_mainSocketfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &socketOptions, sizeof(socketOptions)) < 0) {
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

                if(serverAddr == nullptr || _mainSocketfd < 0)
                    throw std::runtime_error("Init: Failed to create and bind a server socket");

                // Set the server socket to non-blocking mode
                // (For edge-triggered epoll, nonblocking sockets MUST be used)
                if(fcntl(_mainSocketfd, F_SETFL, O_NONBLOCK) < 0)
                    throw std::runtime_error("Init: Failed to set non-blocking mode on the server socket");

                // Put the Server socket in listening mode, waiting to accept new connections
                // (If a connection request arrives when the backlog is full, it will get ECONNREFUSED)
                if(listen(_mainSocketfd, _config.maxConnectionBacklog) < 0)
                    throw std::runtime_error("Init: Failed to initialize listening");

                // Create the epoll instance
                if((_epollfd = epoll_create1(0)) < 0)
                    throw std::runtime_error("Init: Failed to create epoll instance");

                // Setup epoll in edge-triggered (async/non-blocking) mode
                epoll_event mainCtlEvent {};
                mainCtlEvent.data.fd = _mainSocketfd;
                mainCtlEvent.events  = EPOLLIN | EPOLLET;
                if(epoll_ctl(_epollfd, EPOLL_CTL_ADD, _mainSocketfd, &mainCtlEvent) < 0)
                    throw std::runtime_error("Init: Failed to add main socket to epoll instance");
            }

            // -------------------------------------------------------------------------------
            // ---------------------- START THE MAIN SERVER EVENT LOOP -----------------------
            // -------------------------------------------------------------------------------
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
    bool coreConnectionCreateHandler() {
        try {
            sockaddr_storage newClientAddr = {};
            socklen_t newClientAddrSize    = sizeof(newClientAddr);

            // Accept all new connections on the main/listening socket
            // (creates a new client socket and establishes the connection)
            while(true) {
                const rsSocketFd newClientSocketFd = accept(_mainSocketfd, (sockaddr*)&newClientAddr, &newClientAddrSize);
                if(newClientSocketFd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    // No more new connections to accept on the main socket
                    break;
                } else if(newClientSocketFd >= 0) {
                    // Create directly, since cleanup (close + remove from epoll) will happen on deconstruction
                    auto newConnection = std::make_unique<ClientConnection>(newClientSocketFd, _epollfd, newClientAddr);

                    epoll_event epollEvent {};
                    epollEvent.data.fd = newClientSocketFd;
                    epollEvent.events  = EPOLLIN | EPOLLET;
                    // Set the client socket to non-blocking mode and add it to the epoll instance (edge-triggered)
                    const int noblockRes = fcntl(newClientSocketFd, F_SETFL, O_NONBLOCK);
                    const int epollRes   = epoll_ctl(_epollfd, EPOLL_CTL_ADD, newClientSocketFd, &epollEvent);

                    // If the connection is not setup properly and is not moved out to _clientConnections
                    // the socket will be closed and deleted at the end of this scope automatically
                    if(noblockRes >= 0 && epollRes >= 0 && (newConnection->getState() == ClientWebSocketState::Created)) {
                        _logger.log(LogLevel::Debug, ("New client connection created: " + newConnection->getClientAddr()));
                        _clientConnections.insert({ newClientSocketFd, std::move(newConnection) });
                    } else {
                        _logger.log(LogLevel::Error, "Failed to setup new client connection");
                    }
                } else {
                    _logger.log(LogLevel::Error, "Failed to accept new client connection");
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

            // In case of "recv" Error: Initiate the connection close procedure
            if(result.bytesRecv == 0 || result.state == SocketState::ConnectionClose) {
                coreConnectionCloseHandler(client, WsCloseCode::NORMAL_CLOSURE);
                return false;
            } else if(result.state == SocketState::MaxLengthExceeded) {
                coreConnectionCloseHandler(client, WsCloseCode::MESSAGE_TOO_BIG);
                return false;
            } else if(result.state == SocketState::ConnectionReset || result.state == SocketState::Undefined) {
                coreConnectionCloseHandler(client, WsCloseCode::ABNORMAL_CLOSURE);
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
                        coreConnectionCloseHandler(client, WsCloseCode::PROTOCOL_ERROR);
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
                        coreConnectionCloseHandler(client, WsCloseCode::PROTOCOL_ERROR);
                        return false;
                    }

                    // Validate further: Header must have enough bytes for the extended payload length
                    if((tmpPayloadLength == 126 && (bytesRecv < 4)) || (tmpPayloadLength == 127 && (bytesRecv < 10))) {
                        coreConnectionCloseHandler(client, WsCloseCode::PROTOCOL_ERROR);
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
                        coreConnectionCloseHandler(client, WsCloseCode::PROTOCOL_ERROR);
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
                    if(message->opc == WsFrame_OPC::CLOSE) {
                        // In case of a close frame recv from the Client, initiate the connection close procedure
                        coreConnectionCloseHandler(client, WsCloseCode::NORMAL_CLOSURE, true);
                    } else {
                        // In case of a data frame, process the message and send it to the output handler
                        _clientMessageQueue.push(std::move(_messageSegmentationBuffer[client->clientSocketfd]));
                        _messageSegmentationBuffer.erase(client->clientSocketfd);
                    }
                }

                return true;
            }
            return false;
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            coreConnectionCloseHandler(client, WsCloseCode::ABNORMAL_CLOSURE);

            _messageSegmentationBuffer.erase(client->clientSocketfd);

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
                // SPECIAL CASE Handshake:
                // Just send the "raw" bytes, no frame/header (and always just send it as an Echo back to the client)
                const auto result = sendToSocket(message->clientSocketfd, message->getPayload());
                if(result.state == SocketState::OK) {
                    _logger.log(LogLevel::Debug, "Handshake message sent: " + client->getClientAddr());
                    client->setHandshakeCompleted();
                    return true;
                } else {
                    _logger.log(LogLevel::Debug, "Failed to send handshake to client: " + client->getClientAddr());
                    coreConnectionCloseHandler(client.get(), WsCloseCode::PROTOCOL_ERROR);
                    return false;
                }
            } else if(client->getState() == ClientWebSocketState::ClosingServerTrigger ||
                      client->getState() == ClientWebSocketState::ClosingClientTrigger) {
                // SPECIAL CASE Closing:
                // Just send the "raw" bytes, since the closing message was already wrapped in a WS frame
                const auto result = sendToSocket(message->clientSocketfd, message->getPayload());
                if(result.state == SocketState::OK) {
                    _logger.log(LogLevel::Debug, "Close message sent: " + client->getClientAddr());
                    if(client->getState() == ClientWebSocketState::ClosingServerTrigger) {
                        // If the close was triggered from the Server and the Message could be send:
                        //
                        client->setCloseWaitForClient();
                    } else {
                        coreConnectionCloseHandler(client.get(), WsCloseCode::NORMAL_CLOSURE);
                    }
                    return true;
                } else {
                    _logger.log(LogLevel::Debug, "Failed to send close to client: " + client->getClientAddr());
                    coreConnectionCloseHandler(client.get(), WsCloseCode::PROTOCOL_ERROR);
                    return false;
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
                    coreConnectionCloseHandler(client.get(), std::get<WsCloseCode>(result));
                    return false;
                }
            }
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            coreConnectionCloseHandler(client.get(), WsCloseCode::ABNORMAL_CLOSURE);

            _logger.log(LogLevel::Error, "Handle output: " + std::string(e.what()));
            return false;
        }
    }

    void coreConnectionCloseHandler(ClientConnection* const client, WsCloseCode closeCode, bool fromClient = false, std::string&& reason = "") {
        try {
            if(client->getState() == ClientWebSocketState::Created || client->getState() == ClientWebSocketState::Handshake) {
                // In case the connection was not fully established (Handshake not completed)
                // just erase the client from the clientConnections map, which will close/cleanup
                _clientConnections.erase(client->clientSocketfd);
            } else if(client->getState() == ClientWebSocketState::Open && !fromClient) {
                // In case the connection is open, but something went wrong on the server-end, send a close frame to the client
                auto closeFrame = _serverOutputHandler.generateWsCloseFrame(closeCode, std::move(reason));
                auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                _clientMessageQueue.push(std::move(message));
                client->setClosingFromServer();
            } else if(client->getState() == ClientWebSocketState::Open && fromClient) {
                // In case the client wants to close the connection, send a close frame back to the client
                auto closeFrame = _serverOutputHandler.generateWsCloseFrame(closeCode, std::move(reason));
                auto message    = std::make_unique<Message>(client->clientSocketfd, closeFrame.size(), OutputMethod::Echo, closeFrame);
                _clientMessageQueue.push(std::move(message));
                client->setClosingFromClient();
            } else if(client->getState() == ClientWebSocketState::ClosingClientTrigger) {
                // If the client sent a close frame, but the server failed to send one back: Just erase the client
                _clientConnections.erase(client->clientSocketfd);
            } else if(client->getState() == ClientWebSocketState::ClosingServerTrigger) {
                // If the server failed to send the initial close frame: Just erase the client
                _clientConnections.erase(client->clientSocketfd);
            } else if(client->getState() == ClientWebSocketState::ClosingServerWait) {
                // If the server sent a close frame, but the client failed to send one back: Just erase the client
                _clientConnections.erase(client->clientSocketfd);
            } else {
                // Should never be reached, but just in case: Erase the client
                _clientConnections.erase(client->clientSocketfd);
            }
        } catch(const std::exception& e) {
            // In case anything goes wrong: throw away (close) the connection "unclean"
            _clientConnections.erase(client->clientSocketfd);
            _logger.log(LogLevel::Error, "Handle close: " + std::string(e.what()));
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
