#ifndef RESERV_SERVER_CONNECTIONHANDLER_H
#define RESERV_SERVER_CONNECTIONHANDLER_H

#include "enums.hpp"
#include "logger.hpp"
#include "serverConfig.hpp"

#include <algorithm>
#include <map>
#include <memory>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <sys/socket.h>

namespace reServ::Server {

using namespace reServ::Common;

//
// ClientConnection
//
struct ClientConnection {
  public:
    const int clientSocketfd;
    const sockaddr_storage clientAddr;
    const std::string clientAddrStr;

  public:
    ClientConnection(int clientSocketfd, const sockaddr_storage& clientAddr, const std::string& clientAddrStr) :
      clientSocketfd(clientSocketfd), clientAddr(clientAddr), clientAddrStr(clientAddrStr) {}

    ~ClientConnection() = default;
};

//
// ServerConnectionHandler
//
class ServerConnectionHandler {
  private:
    struct BIOFreeAll {
        // unique_ptr custom deleter for OpenSSL BIO
        void operator()(BIO* p) { BIO_free_all(p); }
    };

  public:
    ServerConnectionHandler(const ServerConfig& config) : _config(config), _logger(Logger::instance()) {}

    ~ServerConnectionHandler() = default;

  public:
    std::string handleHandshakeRequest(const std::string& request) const {
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
            response = getResponse_Handshake_NotImplemented();

            // TODO:
            // Check if it makes sense, so setup a "Connection" in case of any other HTTP request
            // (if this Connection is closed immediately this might not be needed - or is it helpful for future use-cases?)
        }
        return response;
    }

  private:
    HandshakeValidationCode validateWebSocketUpgradeHeader(std::string req, std::string supportedWsVersion,
                                                           std::map<std::string, std::string>& headers) const {
        // Remove all whitespace, except line breaks from the request
        req.erase(std::remove_if(req.begin(), req.end(), [](unsigned char x) { return x == '\r' || x == '\t' || x == ' '; }), req.end());

        std::string line, key;
        std::istringstream requestStream(req);
        // Parse the request into a map of headers
        while(std::getline(requestStream, line)) {
            auto separator = line.find(':');
            if(separator != std::string::npos) {
                key = line.substr(0, separator);
                // Transform req header key to lowercase (... for easy comparisons and easy hardcoding)
                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return std::tolower(c); });
                headers[key] = line.substr(separator + 1);
            }
        }

        // Validate the HTTP Request (split at the first line break)
        const std::string httpInfo = req.substr(0, req.find("\n"));
        // TODO
        // ...
        // HTTP version must be 1.1 or higher
        // if(headers["http-version"] != "1.1" && headers["http-version"] != "2.0" && headers["http-version"] != "3.0") {
        //     return ValidationCode::VersionNotSupported;
        // }

        if((headers["upgrade"] != "websocket") || (headers["connection"].find("Upgrade") == std::string::npos) ||
           (headers.find("sec-websocket-key") == headers.end() || headers["sec-websocket-key"].empty())) {
            // Must include "Upgrade: websocket"
            // Must include "Connection: Upgrade"
            // Must include "Sec-WebSocket-Key" with a value
            // ... otherwise: Bad Request
            return HandshakeValidationCode::BadRequest;
        }
        if(headers.find("sec-websocket-version") == headers.end() || headers["sec-websocket-version"] != supportedWsVersion) {
            // Must include "Sec-WebSocket-Version" with a value
            // ... otherwise: Version Not Supported
            return HandshakeValidationCode::VersionNotSupported;
        }
        if(headers.find("origin") == headers.end()) {
            // All browsers send a "Origin" header. This can be validated as well
            // (but this value can also be NULL, so it's not always reliable)
            // ... otherwise: Forbidden
            return HandshakeValidationCode::Forbidden;
        }
        return HandshakeValidationCode::OK;
    }

    std::string createWebSocketAcceptKey(const std::string& webSocketKey) const {
        // 1. Concatenate the request "Sec-WebSocket-Key" with the magic uuid
        const std::string concatenatedKey = webSocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        // 2. Calculate the SHA-1 hash of the combination of those strings
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

    //
    // Check if the request contains the necessary headers for a WebSocket upgrade
    //
    inline bool isWebSocketUpgradeRequest(std::string req) const {
        return (req.find("Upgrade: websocket") != std::string::npos || req.find("upgrade: websocket") != std::string::npos);
    }

    //
    // Check if the request contains any HTTP Method
    // (The comparison "rfind("",0) == 0" is equal to a "string starts with")
    //
    bool isHttpRequest(const std::string& req) const {
        std::string reqUpper;
        reqUpper.resize(req.size());
        std::transform(req.begin(), req.end(), reqUpper.begin(), ::toupper);

        return ((reqUpper.rfind("GET", 0) == 0 || reqUpper.rfind("POST", 0) == 0 || reqUpper.rfind("PUT", 0) == 0 ||
                 reqUpper.rfind("DELETE", 0) == 0 || reqUpper.rfind("CONNECT", 0) == 0 || reqUpper.rfind("HEAD", 0) == 0 ||
                 reqUpper.rfind("OPTIONS", 0) == 0 || reqUpper.rfind("TRACE", 0) == 0) &&
                (reqUpper.find("HTTP/1.1") != std::string::npos || reqUpper.find("HTTP/1.0") != std::string::npos));
    }

  private:
    // --------------------------------------------------------------------------------------------
    // ----------------------------------- HANDSHAKE RESPONSES ------------------------------------
    // --------------------------------------------------------------------------------------------

    // NOT IMPLEMENTED (NOT WEBSOCKET)
    // In case the incoming data is not a HTTP "WebSocket upgrade request" just send a minimal HTTP 1.1 response
    // 501 and close the connection (Version, Status, Content-Type, CORS* and some Content)
    inline std::string getResponse_Handshake_NotImplemented() const {
        return "HTTP/1.1 501 Not Implemented\n"
               "Content-Type: text/plain\n"
               "Access-Control-Allow-Origin: *\n"
               "Connection: close\t\n"
               "Content-Length: 34\n\n"
               "WebSocket Server - no HTTP support";
    }

    // SWITCHING PROTOCOLS
    // - The "default" response is indicating a Upgrade from HTTP to WebSockets (101 Switching Protocols)
    // - Each header line must end with "\r\n" and add an extra "\r\n" at the end to terminate the header
    inline std::string getResponse_Handshake_SwitchingProtocols(const std::string& acceptKey) const {
        return "HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: " +
               std::string(acceptKey) +
               "\r\n"
               "\r\n";
    }

    // BAD REQUEST
    // Send "400 Bad Request" if the header is not understood or has incorrect/missing values
    inline std::string getResponse_Handshake_BadRequest() const {
        return "HTTP/1.1 400 Bad Request\r\n"
               "Content-Type: text/plain\r\n"
               "\r\n"
               "Bad Request: The server could not understand the request due to invalid syntax or missing values.\r\n";
    }

    // FORBIDDEN
    // Send "403 Forbidden", in chase the "Origin" header was checked and deemed invalid
    inline std::string getResponse_Handshake_Forbidden() const {
        return "HTTP/1.1 403 Forbidden\r\n"
               "Content-Type: text/plain\r\n"
               "\r\n"
               "Forbidden: You don't have permission to access on this server.\r\n";
    }

    // UPGRADE REQUIRED
    // Send a "Sec-WebSocket-Version" header back, if the requested version was not supported (with a list of supported versions)
    inline std::string getResponse_UpgradeRequired(const std::string& supportedWsVersion) const {
        return "HTTP/1.1 426 Upgrade Required\r\n"
               "Sec-WebSocket-Version: " +
               std::string(supportedWsVersion) + "\r\n";
    }

  private:
    const ServerConfig _config;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
