#ifndef RESERV_ENUMS_H
#define RESERV_ENUMS_H

#include "types.hpp"

namespace reServ::Common {

enum OutputMethod : rsUInt8 {
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

enum class RecvError {
    OK                = 0,
    ConnectionClose   = 1,
    ConnectionReset   = 2,
    MaxLengthExceeded = 3,
    Timeout           = 4,
    SocketError       = 5
};

enum class SendError {
    OK          = 0,
    BrokenPipe  = 1,
    Timeout     = 2,
    SocketError = 3
};

enum WsFrame_FIN : rsByte {
    CONTINUATION_FRAME = 0x00,
    FINAL_FRAME        = 0x80
};

enum WsFrame_RSV : rsByte {
    // RSV1, RSV2, RSV3 are reserved for further use
    RSV_NONE = 0x00
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

enum WsCloseCode : rsUInt16 {
    CL_NONE                    = 0,
    NORMAL_CLOSURE             = 1000,
    GOING_AWAY                 = 1001,
    PROTOCOL_ERROR             = 1002,
    UNSUPPORTED_DATA           = 1003,
    NO_STATUS_RCVD             = 1005,
    ABNORMAL_CLOSURE           = 1006,
    INVALID_FRAME_PAYLOAD_DATA = 1007,
    POLICY_VIOLATION           = 1008,
    MESSAGE_TOO_BIG            = 1009,
    MANDATORY_EXT              = 1010,
    INTERNAL_SERVER_ERROR      = 1011,
    SERVICE_RESTART            = 1012,
    TRY_AGAIN_LATER            = 1013,
    BAD_GATEWAY                = 1014,
    TLS_HANDSHAKE              = 1015
};

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

} // namespace reServ::Common

#endif
