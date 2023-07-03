#ifndef RESERV_HELPER_H
#define RESERV_HELPER_H

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
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
        char a[INET6_ADDRSTRLEN]{'\0'};
        struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &(addr_v6->sin6_addr), a, INET6_ADDRSTRLEN);
        return std::string(a);
    }
}

//
// Check if the request contains the necessary headers for WebSocket upgrade
// (Convert string to lower and then compare with different "connection" configurations)
//
inline bool isWebSocketUpgradeRequest(std::string req) {
    std::transform(req.begin(), req.end(), req.begin(), [](unsigned char c) { return std::tolower(c); });
    return ((req.find("upgrade: websocket") != std::string::npos && req.find("connection: upgrade") != std::string::npos)
            || (req.find("upgrade: websocket") != std::string::npos && req.find("connection: keep-alive, upgrade") != std::string::npos));
}

}  // namespace reServ

#endif
