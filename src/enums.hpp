#ifndef RESERV_ENUMS_H
#define RESERV_ENUMS_H

#include "types.hpp"

namespace reServ::Common {

enum OutputBehavior : rsUInt8 {
    Echo      = 0,
    Broadcast = 1,
    Custom    = 2
};

// Simple validation codes for the WebSocket handshake
enum class HandshakeValidationCode {
    OK                  = 0,
    BadRequest          = 1,
    Forbidden           = 2,
    VersionNotSupported = 3,
};

enum WsFrame_FIN : rsByte {
    CONTINUATION_FRAME = 0x00,
    FINAL_FRAME        = 0x80
};

enum WsFrame_RSV : rsByte {
    // RSV1, RSV2, RSV3 are reserved for further use
    NO_DATA = 0x00
};

enum WsFrame_OPC : rsByte {
    // 0x3 - 0x7 are reserved for further non-control frames
    // 0xB - 0xF are reserved for further control frames
    CONTINUATION = 0x0,
    TEXT         = 0x1,
    BINARY       = 0x2,
    CLOSE        = 0x8,
    PING         = 0x9,
    PONG         = 0xA
};

enum class LogLevel {
    Info,
    Warning,
    Error
};

} // namespace reServ::Common

#endif
