#ifndef RESERV_CONNECTION_H
#define RESERV_CONNECTION_H

#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "logger.hpp"

namespace reServ {

class Connection {
public:
    Connection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr)
        : _clientSocketfd(clientSocketfd), _clientAddr(clientAddr), _clientAddrStr(clientAddrStr), _logger(Logger::instance()) {}

public:
    virtual bool handleRequest(const std::string& req) = 0;

    inline std::string getAddress() const { return _clientAddrStr; }

    virtual ~Connection() = default;

protected:
    const int _clientSocketfd;
    const sockaddr_storage _clientAddr;
    const std::string _clientAddrStr;
    // Connection Utility
    Logger& _logger;
};

//
// ------------------------------------------------------------------------
// ------------------------------------------------------------------------
// ------------------------------------------------------------------------
//

class HttpConnection : public Connection {
public:
    HttpConnection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr)
        : Connection(clientSocketfd, clientAddr, clientAddrStr) {}

public:
    bool handleRequest(const std::string& req) override {
        try {
            // -------------------------------------------------------
            // Here could be any HTTP Server Logic:
            // - Parse request Method (GET, POST, PUT, DELETE)
            // - Parse request Content (text, json, html, file, ...)
            // - Create a Server response, based on the Client request
            // -------------------------------------------------------

            // In case the incoming data is not a HTTP "WebSocket upgrade request"
            // just send a minimal HTTP 1.1 response 501 and close the connection
            // (Version, Status, Content-Type, CORS* and some Content)
            const char* res = "HTTP/1.1 501 Not Implemented\n"
                              "Content-Type: text/plain\n"
                              "Access-Control-Allow-Origin: *\n"
                              "Connection: close\t\n"
                              "Content-Length: 34\n\n"
                              "WebSocket Server - no HTTP support";

            ssize_t bytesWritten = send(_clientSocketfd, res, std::strlen(res), 0);
            if(bytesWritten < 0) {
                _logger.log(LogLevel::Warning, "Could not write to Client: " + _clientAddrStr);
                return false;
            }
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "HTTP Connection: " + std::string(e.what()));
            return false;
        }
    }
};

//
// ------------------------------------------------------------------------
// ------------------------------------------------------------------------
// ------------------------------------------------------------------------
//

class WebSocketConnection : public Connection {
public:
    WebSocketConnection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr)
        : Connection(clientSocketfd, clientAddr, clientAddrStr) {}

public:
    // bool handleHandshake(const std::string& req) override {
    //     // Upgrade the connection to WebSocket and send the upgrade response to the client
    //     std::string response = "HTTP/1.1 101 Switching Protocols\r\n";
    //     response += "Upgrade: websocket\r\n";
    //     response += "Connection: Upgrade\r\n";
    //     response += "Sec-WebSocket-Accept: <websocket key>\r\n";
    //     response += "\r\n";

    //     ssize_t bytesWritten = send(_clientSocketfd, response.c_str(), response.length(), 0);
    //     if(bytesWritten < 0)
    //         return false;

    //     return true;
    // }

    bool handleRequest(const std::string& req) override {
        try {
            // Perform WebSocket handshake
            // if(performWebSocketHandshake(req)) {
            //     std::vector<char> buffer(1024);

            //     while(true) {
            //         // Read WebSocket frame header
            //         ssize_t bytesRead = read(_clientSocketfd, buffer.data(), 2);
            //         if(bytesRead < 0) {
            //             std::cerr << "Error reading WebSocket frame header" << std::endl;
            //             return;
            //         }

            //         if(bytesRead == 0) {
            //             // WebSocket connection closed
            //             std::cout << "WebSocket connection closed" << std::endl;
            //             return;
            //         }

            //         unsigned char opcode = buffer[0] & 0x0F;
            //         bool isMasked = buffer[1] & 0x80;
            //         uint64_t payloadLength = buffer[1] & 0x7F;

            //         if(payloadLength == 126) {
            //             // Extended payload length (16-bit)
            //             bytesRead = read(_clientSocketfd, buffer.data(), 2);
            //             if(bytesRead < 0) {
            //                 std::cerr << "Error reading WebSocket frame payload length" << std::endl;
            //                 return;
            //             }

            //             payloadLength = ntohs(*reinterpret_cast<uint16_t*>(buffer.data()));
            //         } else if(payloadLength == 127) {
            //             // Extended payload length (64-bit)
            //             bytesRead = read(_clientSocketfd, buffer.data(), 8);
            //             if(bytesRead < 0) {
            //                 std::cerr << "Error reading WebSocket frame payload length" << std::endl;
            //                 return;
            //             }

            //             payloadLength = be64toh(*reinterpret_cast<uint64_t*>(buffer.data()));
            //         }

            //         std::cout << "Received WebSocket frame:" << std::endl;
            //         std::cout << "Opcode: " << static_cast<unsigned int>(opcode) << std::endl;
            //         std::cout << "Payload Length: " << payloadLength << std::endl;

            //         // Read payload data
            //         if(isMasked) {
            //             // Read mask key
            //             bytesRead = read(_clientSocketfd, buffer.data(), 4);
            //             if(bytesRead < 0) {
            //                 std::cerr << "Error reading WebSocket frame mask key" << std::endl;
            //                 return;
            //             }
            //         }

            //         std::vector<char> payloadData(payloadLength);
            //         bytesRead = read(_clientSocketfd, payloadData.data(), payloadLength);
            //         if(bytesRead < 0) {
            //             std::cerr << "Error reading WebSocket frame payload data" << std::endl;
            //             return;
            //         }

            //         std::cout << "Payload Data:" << std::endl;
            //         std::cout.write(payloadData.data(), payloadData.size());
            //         std::cout << std::endl;

            //         //
            //         // Text message (opcode 0x01): The payload data is treated as a text message, and it can be processed accordingly.
            //         // Binary message (opcode 0x02): The payload data is treated as a binary message, and it can be processed accordingly.
            //         // Close frame (opcode 0x08): The WebSocket connection is closed, and the function returns.
            //         //

            //         // Handle different types of WebSocket messages
            //         if(opcode == 0x01) {
            //             // Text message
            //             std::string textMessage(payloadData.begin(), payloadData.end());
            //             std::cout << "Received Text Message: " << textMessage << std::endl;

            //             // Process the text message
            //             // ...
            //         } else if(opcode == 0x02) {
            //             // Binary message
            //             std::cout << "Received Binary Message" << std::endl;

            //             // Process the binary message
            //             // ...
            //         } else if(opcode == 0x08) {
            //             // Close connection
            //             std::cout << "Received Close Frame" << std::endl;

            //             // Close the WebSocket connection
            //             // Remove client socket from the set of connected clients
            //             // connectedClients_.erase(_clientSocketfd);
            //             // ...

            //             return;
            //         } else {
            //             // Unsupported opcode
            //             std::cerr << "Received unsupported WebSocket opcode: " << static_cast<unsigned int>(opcode) << std::endl;

            //             // Handle or ignore the unsupported opcode
            //             // ...
            //         }

            //         // Forward WebSocket frame to other connected clients
            //         forwardWebSocketFrame(buffer, bytesRead);
            //     }
            // }
            return true;
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "WebSocket Connection: " + std::string(e.what()));
            return false;
        }
    }

private:
    /*
    bool performWebSocketHandshake(const std::string& request) {
        // // Extract the WebSocket key from the request
        // std::string key;
        // size_t keyPos = request.find("Sec-WebSocket-Key: ");
        // if(keyPos != std::string::npos) {
        //     keyPos += 19;  // Length of "Sec-WebSocket-Key: "
        //     size_t keyEndPos = request.find("\r\n", keyPos);
        //     if(keyEndPos != std::string::npos) {
        //         key = request.substr(keyPos, keyEndPos - keyPos);
        //     }
        // }

        // if(key.empty()) {
        //     std::cerr << "Invalid WebSocket upgrade request" << std::endl;
        //     return false;
        // }

        // // Generate the WebSocket accept key
        // std::string acceptKey = generateWebSocketAcceptKey(key);

        // // Construct the WebSocket upgrade response
        // std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
        //                        "Upgrade: websocket\r\n"
        //                        "Connection: Upgrade\r\n"
        //                        "Sec-WebSocket-Accept: "
        //                        + acceptKey + "\r\n"
        //                                      "\r\n";

        // // Send the WebSocket upgrade response
        // ssize_t bytesWritten = write(_clientSocketfd, response.c_str(), response.size());
        // if(bytesWritten < 0) {
        //     std::cerr << "Error writing WebSocket upgrade response" << std::endl;
        //     return false;
        // }

        // std::cout << "WebSocket upgrade response sent" << std::endl;

        return true;
    }

    std::string generateWebSocketAcceptKey(const std::string& key) {
        // Concatenate the WebSocket key with the WebSocket GUID and calculate the SHA-1 hash
        std::string concatenatedKey = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::vector<unsigned char> sha1Hash(20);
        // Calculate SHA-1 hash of the concatenated key here (not shown)

        // Base64-encode the SHA-1 hash to generate the accept key
        std::string acceptKey;
        // Base64-encode the SHA-1 hash to acceptKey here (not shown)

        return acceptKey;
    }
    */
};

}  // namespace reServ

#endif
