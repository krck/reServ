#ifndef RESERV_HELPERS_H
#define RESERV_HELPERS_H

#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>

namespace reServ::Common {

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

} // namespace reServ::Common

#endif
