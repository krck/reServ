#ifndef RESERV_ENUMS_H
#define RESERV_ENUMS_H

#include "types.hpp"

namespace reServ::Common {

// -------------------------------------------------------------------
// -------------------------- ENUM CLASSES ---------------------------
// -------------------------------------------------------------------

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

enum class ClientWebSocketState {
    Created,
    Handshake,
    Open,
    Closing,
    Closed
};

// Handshake validation results
// (Based on HTTP status codes, since Handshake is an HTTP request)
enum class HandshakeState {
    OK,
    BadRequest,
    Forbidden,
    VersionNotSupported,
};

// TCP Socket send/recv states
enum class SocketState {
    OK,
    ConnectionClose,
    ConnectionReset,
    MaxLengthExceeded,
    BrokenPipe,
    Timeout,
    Undefined,
};

enum class OutputMethod {
    Echo,
    Broadcast,
    Custom
};

// -------------------------------------------------------------------
// ------------------------ INT ENUM TYPES ---------------------------
// -------------------------------------------------------------------

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

} // namespace reServ::Common

#endif
