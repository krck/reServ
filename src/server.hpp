#ifndef RESERV_SERVER_H
#define RESERV_SERVER_H

#include "clientConnection.hpp"
#include "closeCondition.hpp"
#include "configService.hpp"
#include "enums.hpp"
#include "helpers.hpp"
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
      _epollfd(-1), _mainSocketfd(-1), _config(ConfigService::instance().getServerConfig()), _serverAddrListFull(nullptr), _clientCloseQueue(),
      _clientMessageQueue(), _messageSegmentationBuffer(), _clientConnections(), _serverConnectionHandler(ServerConnectionHandler()),
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
                const auto result = sendToSocket(newClientSocketFd, respBytes);
                if(result.bytesSent >= 0) {
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
            std::vector<rsByte> recvBuf;
            auto result = recvFromSocket(client->clientSocketfd, recvBuf);
            if(result.bytesRecv == 0 || result.error == RecvError::ConnectionClose) {
                _clientCloseQueue.push({ client->clientSocketfd, true, "NORMAL_CLOSURE", WsCloseCode::NORMAL_CLOSURE });
                return false;
            } else if(result.error == RecvError::MaxLengthExceeded) {
                _clientCloseQueue.push({ client->clientSocketfd, true, "MESSAGE_TOO_BIG", WsCloseCode::MESSAGE_TOO_BIG });
                return false;
            } else if(result.error == RecvError::ConnectionReset || result.error == RecvError::SocketError) {
                _clientCloseQueue.push({ client->clientSocketfd, true, "ABNORMAL_CLOSURE", WsCloseCode::ABNORMAL_CLOSURE });
                return false;
            }

            // ---------------------------------------------- CREATE NEW MESSAGE -----------------------------------------------
            // -- If no uncompleted segment exists, then this is the beginning of a new message and the header must be parsed --
            // -----------------------------------------------------------------------------------------------------------------
            rsUInt64 headerFrameSize = 0;
            const rsInt64 bytesRecv  = result.bytesRecv;
            if(_messageSegmentationBuffer.find(client->clientSocketfd) == _messageSegmentationBuffer.end()) {
                // Validate if we have a complete WebSocket frame
                // (must be at least two bytes for a basic header)
                if(bytesRecv < 2) {
                    _clientCloseQueue.push({ client->clientSocketfd, true, "Incomplete Header", WsCloseCode::PROTOCOL_ERROR });
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
                    _clientCloseQueue.push({ client->clientSocketfd, true, "Client frame with mask bit set 0", WsCloseCode::PROTOCOL_ERROR });
                    return false;
                }

                // Validate further: Header must have enough bytes for the extended payload length
                if((tmpPayloadLength == 126 && (bytesRecv < 4)) || (tmpPayloadLength == 127 && (bytesRecv < 10))) {
                    _clientCloseQueue.push({ client->clientSocketfd, true, "Incomplete Header", WsCloseCode::PROTOCOL_ERROR });
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
                    _clientCloseQueue.push({ client->clientSocketfd, true, "Incomplete Header", WsCloseCode::PROTOCOL_ERROR });
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
                auto message = std::make_unique<ClientMessage>(client->clientSocketfd, fin, rsv, opc, maskingKey, actualPayloadLength);
                _messageSegmentationBuffer.insert({ client->clientSocketfd, std::move(message) });
            }

            // --------------------------------------- APPEND SEGMENT DATA TO THE MESSAGE --------------------------------------
            // -- Get the message segment for this client and append the received data. Then check if the message is complete --
            // -----------------------------------------------------------------------------------------------------------------
            auto& message = _messageSegmentationBuffer[client->clientSocketfd];
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
                _clientMessageQueue.push(std::move(message));
                _messageSegmentationBuffer.erase(client->clientSocketfd);
                return true;
            }
        } catch(const std::exception& e) {
            // Close the connection in case recv returned 0 or a error was thrown
            _clientCloseQueue.push({ client->clientSocketfd, true, "ABNORMAL_CLOSURE", WsCloseCode::ABNORMAL_CLOSURE });
            _messageSegmentationBuffer.erase(client->clientSocketfd);

            _logger.log(LogLevel::Error, "Handle input: " + std::string(e.what()));
            return false;
        }
    }

    bool coreOutputHandler(const ClientMessage* const message) {
        try {
            // The client connection was closed in the meantime, so the message should not be sent
            if(_clientConnections.find(message->clientSocketfd) == _clientConnections.end() || message == nullptr) {
                return false;
            }

            // Based on the input message, generate a output message (WebSocket frame)
            auto result = _serverOutputHandler.generateWsDataFrame(_clientConnections[message->clientSocketfd].get(), message);
            if(std::holds_alternative<std::vector<rsByte>>(result)) {
                const std::vector<rsByte>& outputMessage = std::get<std::vector<rsByte>>(result);
                if(_config.outputMethod == OutputMethod::Echo) {
                    // Echo the message back to the client (if it still exists in the clientConnections)
                    auto clientIter = _clientConnections.find(message->clientSocketfd);
                    if(clientIter != _clientConnections.end()) {
                        const auto result = sendToSocket(message->clientSocketfd, outputMessage);

                        _logger.log(LogLevel::Debug, "Echo message sent: " + std::to_string(result.bytesSent));
                        // _logger.log(LogLevel::Debug, "Echo message: " + std::string(outputMessage.begin(), outputMessage.end()));

                        if(result.bytesSent < 0) {
                            // throw std::runtime_error("Failed to send message to client: " + clientIter->second->clientAddrStr);
                            // ...
                        }
                    }
                } else if(_config.outputMethod == OutputMethod::Broadcast) {
                    // Broadcast the message to all clients
                    for(auto& client: _clientConnections) {
                        const auto result = sendToSocket(client.second->clientSocketfd, outputMessage);
                        if(result.bytesSent < 0) {
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

            _logger.log(LogLevel::Error, "Handle output: " + std::string(e.what()));
            return false;
        }
    }

    bool coreConnectionCloseHandler(const CloseCondition& condition) {
        try {
            if(condition.wsConnectionEstablished) {
                // Send a WebSocket close frame to the client
                std::vector<rsByte> closeFrame = _serverOutputHandler.generateWsCloseFrame(static_cast<rsUInt16>(condition.closeCode));
                const auto result              = sendToSocket(condition.clientSocketfd, closeFrame);
                if(result.bytesSent < 0) {
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
    struct SendResult {
        const rsInt64 bytesSent;
        const SendError error;
    };
    SendResult sendToSocket(int clientSocketfd, const std::vector<rsByte>& sendBuf, int flags = 0) noexcept {
        rsInt64 totalBytesSent = 0;
        while(totalBytesSent < sendBuf.size()) {
            // Call send with MSG_NOSIGNAL to prevent the send function from raising a SIGPIPE signal
            // (instead it will return -1 and set errno to EPIPE if the connection is broken)
            rsInt64 bytesSent = send(clientSocketfd, &sendBuf[totalBytesSent], sendBuf.size() - totalBytesSent, flags | MSG_NOSIGNAL);
            if(bytesSent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // The send would block, so wait a bit and try again
                // Wait for 1 millisecond (1000 microseconds)
                usleep(1000);
                continue;
            } else if(bytesSent == -1 && errno == EPIPE) {
                // Handle broken pipe error
                _logger.log(LogLevel::Error, "Broken pipe error: " + std::string(strerror(errno)));
                return { totalBytesSent, SendError::BrokenPipe };
            } else if(bytesSent == -1) {
                // Handle other errors
                _logger.log(LogLevel::Error, "Socket error: " + std::string(strerror(errno)));
                return { totalBytesSent, SendError::SocketError };
            }
            totalBytesSent += bytesSent;
        }
        return { totalBytesSent, SendError::OK };
    }

    //
    // Recv Wrapper
    //
    struct RecvResult {
        const rsInt64 bytesRecv;
        const RecvError error;
    };
    RecvResult recvFromSocket(int clientSocketfd, std::vector<rsByte>& recvBuf, int flags = 0) noexcept {
        rsInt64 totalBytesRecv = 0;
        rsInt64 bytesRecv      = 0;

        // Clear and resize the buffer (swap-and-clear)
        std::vector<rsByte>(_config.recvBufferSize).swap(recvBuf);
        const int rFlags = (flags | MSG_DONTWAIT | MSG_NOSIGNAL);

        // Receive incoming data, until there is no more data to read on the client socket
        while((bytesRecv = recv(clientSocketfd, &recvBuf[totalBytesRecv], recvBuf.size() - totalBytesRecv, rFlags)) > 0) {
            if(bytesRecv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // The recv would block, so wait a bit and try again
                // Wait for 1 millisecond (1000 microseconds)
                usleep(1000);
                continue;
            } else if(bytesRecv == -1 && errno == ECONNRESET) {
                // Handle connection reset by peer
                _logger.log(LogLevel::Error, "Connection reset by peer: " + std::string(strerror(errno)));
                return { totalBytesRecv, RecvError::ConnectionReset };
            } else if(bytesRecv == -1) {
                // Handle other errors
                _logger.log(LogLevel::Error, "Socket error: " + std::string(strerror(errno)));
                return { totalBytesRecv, RecvError::SocketError };
            } else if(bytesRecv == 0) {
                // Handle connection closed by client
                _logger.log(LogLevel::Error, "Connection closed by client: " + std::string(strerror(errno)));
                return { totalBytesRecv, RecvError::ConnectionClose };
            }

            totalBytesRecv += bytesRecv;

            // Resize the buffer if its full (scale by always doubling the size to reduce allocation overhead)
            if(totalBytesRecv == (rsInt64)recvBuf.size()) {
                // Check for buffer overflow (if buffer is too large, close the connection)
                if(recvBuf.size() * 2 > (rsUInt64)(_config.maxPayloadLength + _config.frameHeaderSize)) {
                    _logger.log(LogLevel::Error, "Max length exceeded: " + std::to_string(totalBytesRecv));
                    return { totalBytesRecv, RecvError::MaxLengthExceeded };
                }
                recvBuf.resize(recvBuf.size() * 2);
            }
        }

        return { totalBytesRecv, RecvError::OK };
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
    std::unordered_map<int, std::unique_ptr<ClientMessage>> _messageSegmentationBuffer;
    std::unordered_map<int, std::unique_ptr<ClientConnection>> _clientConnections;
    // Server Utility
    const ServerConnectionHandler _serverConnectionHandler;
    const ServerOutputHandler _serverOutputHandler;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
