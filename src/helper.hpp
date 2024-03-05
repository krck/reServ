#ifndef RESERV_HELPER_H
#define RESERV_HELPER_H

#include <algorithm>
#include <arpa/inet.h>
#include <netinet/in.h>
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
    return ((req.rfind("GET", 0) == 0 || req.rfind("POST", 0) == 0 || req.rfind("PUT", 0) == 0 || req.rfind("DELETE", 0) == 0 ||
             req.rfind("CONNECT", 0) == 0 || req.rfind("HEAD", 0) == 0 || req.rfind("OPTIONS", 0) == 0 || req.rfind("TRACE", 0) == 0) &&
            req.find("HTTP") != std::string::npos);
}

} // namespace reServ

#endif
