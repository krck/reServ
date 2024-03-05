#ifndef RESERV_CONNECTION_H
#define RESERV_CONNECTION_H

#include "logger.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <map>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>

namespace reServ {

class Connection {
  public:
    Connection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr)
        : _clientSocketfd(clientSocketfd), _clientAddr(clientAddr), _clientAddrStr(clientAddrStr), _logger(Logger::instance()) {}

  public:
    virtual bool handleHandshake(const std::string& req) = 0;
    virtual bool handleRequest(const std::string& req)   = 0;

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
    bool handleHandshake(const std::string&) override {
        try {
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

    bool handleRequest(const std::string& req) override {
        // -------------------------------------------------------
        // Here could be any HTTP Server Logic:
        // - Parse request Method (GET, POST, PUT, DELETE)
        // - Parse request Content (text, json, html, file, ...)
        // - Create a Server response, based on the Client request
        // -------------------------------------------------------

        // But since this is a WebSocket Server, this should have never gotten here
        return handleHandshake(req);
    }
};

//
// ------------------------------------------------------------------------
// ------------------------------------------------------------------------
// ------------------------------------------------------------------------
//

class WebSocketConnection : public Connection {
  private:
    // unique_ptr custom deleter for OpenSSL BIO
    struct BIOFreeAll {
        void operator()(BIO* p) { BIO_free_all(p); }
    };

    // Simple validation codes for the WebSocket handshake
    enum class ValidationCode {
        OK                  = 0,
        BadRequest          = 1,
        Forbidden           = 2,
        VersionNotSupported = 3,
    };

  public:
    WebSocketConnection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr,
                        const std::string& supportedWsVersion)
        : Connection(clientSocketfd, clientAddr, clientAddrStr), _supportedWsVersion(supportedWsVersion) {}

  public:
    bool handleHandshake(const std::string& req) override {
        std::map<std::string, std::string> reqHeaders;
        const ValidationCode validationCode = validateWebSocketUpgradeHeader(req, reqHeaders);

        std::ostringstream httpResponseStream;
        if(validationCode == ValidationCode::OK) {
            // The "Sec-WebSocket-Accept" header must be created and added to the response
            std::string acceptKey = createWebSocketAcceptKey(reqHeaders["sec-websocket-key"]);

            // Send Handshake Response:
            // - The "default" response is indicating a Upgrade from HTTP to WebSockets (101 Switching Protocols)
            // - Each header line must end with "\r\n" and add an extra "\r\n" at the end to terminate the header
            httpResponseStream << "HTTP/1.1 101 Switching Protocols\r\n"
                               << "Upgrade: websocket\r\n"
                               << "Connection: Upgrade\r\n"
                               << "Sec-WebSocket-Accept: " << acceptKey << "\r\n"
                               << "\r\n"
                               << "";
        } else if(validationCode == ValidationCode::BadRequest) {
            // Send "400 Bad Request" if the header is not understood or has incorrect/missing values
            httpResponseStream << "HTTP/1.1 400 Bad Request\r\n"
                               << "Content-Type: text/plain\r\n"
                               << "\r\n"
                               << "Bad Request: The server could not understand the request due to invalid syntax or missing values.\r\n"
                               << "";
        } else if(validationCode == ValidationCode::Forbidden) {
            // Send "403 Forbidden", in chase the "Origin" header was checked and deemed invalid
            httpResponseStream << "HTTP/1.1 403 Forbidden\r\n"
                               << "Content-Type: text/plain\r\n"
                               << "\r\n"
                               << "Forbidden: You don't have permission to access on this server.\r\n"
                               << "";

        } else if(validationCode == ValidationCode::VersionNotSupported) {
            // Send a "Sec-WebSocket-Version" header back, if the requested version was not supported (with a list of supported versions)
            httpResponseStream << "HTTP/1.1 426 Upgrade Required\r\n"
                               << "Sec-WebSocket-Version: " << _supportedWsVersion << "\r\n"
                               << "Content-Type: text/plain\r\n"
                               << "\r\n"
                               << "Upgrade Required: The server cannot establish a WebSocket connection using the version specified.\r\n"
                               << "";
        }

        const std::string response = httpResponseStream.str();
        ssize_t bytesWritten       = send(_clientSocketfd, response.c_str(), response.length(), 0);
        return (bytesWritten < 0);
    }

    bool handleRequest(const std::string& req) override {
        try {
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

            // return true;

            return (req.length() > 0);
        } catch(const std::exception& e) {
            _logger.log(LogLevel::Error, "WebSocket Connection: " + std::string(e.what()));
            return false;
        }
    }

  private:
    ValidationCode validateWebSocketUpgradeHeader(std::string req, std::map<std::string, std::string>& headers) {
        // Remove all whitespace, except line breaks from the request
        req.erase(std::remove_if(req.begin(), req.end(), [](unsigned char x) { return x == '\r' || x == '\t' || x == ' '; }), req.end());

        std::string line, key;
        std::istringstream requestStream(req);
        // Parse the request into a map of headers
        while(std::getline(requestStream, line)) {
            auto separator = line.find(':');
            if(separator != std::string::npos) {
                // Transform req header key to lowercase (... for easy comparisons and easy hardcoding :P)
                key = line.substr(0, separator);
                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return std::tolower(c); });
                headers[key] = line.substr(separator + 1);
            }
        }

        // Validate the HTTP Request (split at the first linebreak)
        const std::string httpInfo = req.substr(0, req.find("\n"));
        // TODO
        // ...
        // HTTP version must be 1.1 or higher
        // if(headers["http-version"] != "1.1" && headers["http-version"] != "2.0" && headers["http-version"] != "3.0") {
        //     return ValidationCode::VersionNotSupported;
        // }

        if(
            // Must include "Upgrade: websocket"
            (headers["upgrade"] != "websocket")
            // Must include "Connection: Upgrade"
            || (headers["connection"].find("Upgrade") == std::string::npos)
            // Must include "Sec-WebSocket-Key" with a value
            || (headers.find("sec-websocket-key") == headers.end() || headers["sec-websocket-key"].empty())
            // Bad Request
        ) {
            return ValidationCode::BadRequest;
        }

        if(
            // Must include "Sec-WebSocket-Version" with a value
            headers.find("sec-websocket-version") == headers.end() || headers["sec-websocket-version"] != _supportedWsVersion
            // Version Not Supported
        ) {
            return ValidationCode::VersionNotSupported;
        }

        if(
            // All browsers send a "Origin" header. This can be validated as well
            // (but this value can also be NULL, so it's not always reliable)
            headers.find("origin") == headers.end()
            // Forbidden
        ) {
            return ValidationCode::Forbidden;
        }

        return ValidationCode::OK;
    }

    std::string createWebSocketAcceptKey(const std::string& webSocketKey) {
        // 1. Concatenate the request "Sec-WebSocket-Key" with the magic uuid
        const std::string concatenatedKey = webSocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        // 2. Calculate the SHA-1 hash of the combination of those strings
        char hex[3];
        std::stringstream ss;
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)concatenatedKey.c_str(), concatenatedKey.length(), hash);

        // 3. Base-64 encode the calculated hash and add the result as the "Sec-WebSocket-Accept" key
        std::unique_ptr<BIO, BIOFreeAll> b64(BIO_new(BIO_f_base64()));
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
        BIO* sink = BIO_new(BIO_s_mem());
        BIO_push(b64.get(), sink);
        BIO_write(b64.get(), hash, SHA_DIGEST_LENGTH);
        BIO_flush(b64.get());
        const char* encoded;
        const long len = BIO_get_mem_data(sink, &encoded);

        return std::string(encoded, len);
    }

  private:
    const std::string& _supportedWsVersion;
};

} // namespace reServ

#endif
