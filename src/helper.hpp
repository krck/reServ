#ifndef RESERV_HELPER_H
#define RESERV_HELPER_H

#include "enums.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>

namespace reServ {

//
// Return a IPv4/IPv6 address as a (readable) string
//
std::string extractIpAddrString(sockaddr_storage* addr) {
    if(addr->ss_family == AF_INET) {
        // IP v4 Address
        struct sockaddr_in* addr_v4 = (struct sockaddr_in*)addr;
        return std::string(inet_ntoa(addr_v4->sin_addr));
    } else {
        // IP v6 Address
        char a[INET6_ADDRSTRLEN] { '\0' };
        struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &(addr_v6->sin6_addr), a, INET6_ADDRSTRLEN);
        return std::string(a);
    }
}

//
// Check if the request contains the necessary headers for a WebSocket upgrade
//
bool isWebSocketUpgradeRequest(std::string req) {
    return (req.find("Upgrade: websocket") != std::string::npos || req.find("upgrade: websocket") != std::string::npos);
}

//
// Check if the request contains any HTTP Method
// (The comparison "rfind("",0) == 0" is equal to a "string start with")
//
bool isHttpRequest(const std::string& req) {
    std::string reqUpper;
    reqUpper.resize(req.size());
    std::transform(req.begin(), req.end(), reqUpper.begin(), ::toupper);

    return ((reqUpper.rfind("GET", 0) == 0 || reqUpper.rfind("POST", 0) == 0 || reqUpper.rfind("PUT", 0) == 0 || reqUpper.rfind("DELETE", 0) == 0 ||
             reqUpper.rfind("CONNECT", 0) == 0 || reqUpper.rfind("HEAD", 0) == 0 || reqUpper.rfind("OPTIONS", 0) == 0 ||
             reqUpper.rfind("TRACE", 0) == 0) &&
            (reqUpper.find("HTTP/1.1") != std::string::npos || reqUpper.find("HTTP/1.0") != std::string::npos));
}

HandshakeValidationCode validateWebSocketUpgradeHeader(std::string req, std::string supportedWsVersion, std::map<std::string, std::string>& headers) {
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
        return HandshakeValidationCode::BadRequest;
    }

    if(
        // Must include "Sec-WebSocket-Version" with a value
        headers.find("sec-websocket-version") == headers.end() || headers["sec-websocket-version"] != supportedWsVersion
        // Version Not Supported
    ) {
        return HandshakeValidationCode::VersionNotSupported;
    }

    if(
        // All browsers send a "Origin" header. This can be validated as well
        // (but this value can also be NULL, so it's not always reliable)
        headers.find("origin") == headers.end()
        // Forbidden
    ) {
        return HandshakeValidationCode::Forbidden;
    }

    return HandshakeValidationCode::OK;
}

// unique_ptr custom deleter for OpenSSL BIO
struct BIOFreeAll {
    void operator()(BIO* p) { BIO_free_all(p); }
};
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

} // namespace reServ

#endif
