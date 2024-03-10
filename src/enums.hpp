#ifndef RESERV_ENUMS_H
#define RESERV_ENUMS_H

namespace reServ::Common {

// Simple validation codes for the WebSocket handshake
enum class HandshakeValidationCode {
    OK                  = 0,
    BadRequest          = 1,
    Forbidden           = 2,
    VersionNotSupported = 3,
};

} // namespace reServ::Common

#endif
