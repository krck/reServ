#ifndef RESERV_RESPONSE_MESSAGES_H
#define RESERV_RESPONSE_MESSAGES_H

#include <string>

namespace reServ {

// --------------------------------------------------------------------------------------------
// ----------------------------------- HANDSHAKE RESPONSES ------------------------------------
// --------------------------------------------------------------------------------------------

// NOT IMPLEMENTED (NOT WEBSOCKET)
// In case the incoming data is not a HTTP "WebSocket upgrade request" just send a minimal HTTP 1.1 response
// 501 and close the connection (Version, Status, Content-Type, CORS* and some Content)
inline std::string getResponse_Handshake_NotImplemented() {
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
inline std::string getResponse_Handshake_SwitchingProtocols(const std::string& acceptKey) {
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
inline std::string getResponse_Handshake_BadRequest() {
    return "HTTP/1.1 400 Bad Request\r\n"
           "Content-Type: text/plain\r\n"
           "\r\n"
           "Bad Request: The server could not understand the request due to invalid syntax or missing values.\r\n";
}

// FORBIDDEN
// Send "403 Forbidden", in chase the "Origin" header was checked and deemed invalid
inline std::string getResponse_Handshake_Forbidden() {
    return "HTTP/1.1 403 Forbidden\r\n"
           "Content-Type: text/plain\r\n"
           "\r\n"
           "Forbidden: You don't have permission to access on this server.\r\n";
}

// UPGRADE REQUIRED
// Send a "Sec-WebSocket-Version" header back, if the requested version was not supported (with a list of supported versions)
inline std::string getResponse_UpgradeRequired(const std::string& supportedWsVersion) {
    return "HTTP/1.1 426 Upgrade Required\r\n"
           "Sec-WebSocket-Version: " +
           std::string(supportedWsVersion) + "\r\n";
}

} // namespace reServ

#endif
