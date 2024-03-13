#ifndef RESERV_SERVER_INPUTHANDLER_H
#define RESERV_SERVER_INPUTHANDLER_H

#include "enums.hpp"
#include "logger.hpp"
#include "serverConfig.hpp"
#include "types.hpp"

#include <string>
#include <vector>

namespace reServ::Server {

using namespace reServ::Common;

//
// ClientMessage
//
struct ClientMessage {
  public:
    const int clientSocketfd;
    const WsFrame_FIN fin;
    const WsFrame_RSV rsv;
    const WsFrame_OPC opc; // OpCode
    const std::string payloadPlainText;

  public:
    ClientMessage(int clientSocketfd, WsFrame_FIN fin, WsFrame_RSV rsv, WsFrame_OPC opc, const std::string& payloadPlainText) :
      clientSocketfd(clientSocketfd), fin(fin), rsv(rsv), opc(opc), payloadPlainText(payloadPlainText) {}

    ~ClientMessage() = default;
};

//
// ServerInputHandler
//
class ServerInputHandler {
  public:
    ServerInputHandler(const ServerConfig& config) : _config(config), _logger(Logger::instance()) {}

    ~ServerInputHandler() = default;

  public:
    ClientMessage handleInputData(int clientSocketfd, const std::vector<rsByte>& recvBuffer) const {
        // Add some logic for "split" messages here
        // WebSocket: Message only ends, when the FIN bit is set (one client can send multiple messages in one packet)
        // ...
        // Caching logic, that stores the last message per "clientSocketfd" and appends the new one to it, if the FIN bit is not set
        // Only if the FIN bit is set, the message is returned to the server, where it is then added to the message queue
        // ...

        auto message = parseWsFrame(clientSocketfd, recvBuffer);
        return message;
    }

  private:
    ClientMessage parseWsFrame(int clientSocketfd, const std::vector<rsByte>& messageBytes) const {
        // ----------------------------------------------------------------------------------------------------------------
        // ---------------------------------------- Parse WebSocket Protocol Data -----------------------------------------
        // ------------------------------- https://www.rfc-editor.org/rfc/rfc6455#section-5 -------------------------------
        // ----------------------------------------------------------------------------------------------------------------

        // The first BYTE contains the FIN bit, RSV1, RSV2, RSV3, and the OP-Code
        // |7|6|5|4|3|2|1|0|
        // |F|R|R|R| opcode|
        const WsFrame_FIN fin = static_cast<WsFrame_FIN>(messageBytes[0] & 0x80); // 0b10000000
        const WsFrame_RSV rsv = static_cast<WsFrame_RSV>(messageBytes[0] & 0x70); // 0b01110000
        const WsFrame_OPC opc = static_cast<WsFrame_OPC>(messageBytes[0] & 0x0F); // 0b00001111

        // The second BYTE contains the MASK bit and the payload length
        // |7|6|5|4|3|2|1|0|
        // |M| Payload len |
        const bool maskBitSet     = static_cast<bool>(messageBytes[1] & 0x80);     // 0b10000000
        rsUInt64 tmpPayloadLength = static_cast<rsUInt64>(messageBytes[1] & 0x7F); // 0b01111111

        // Use the original payload length to determine how many of the bytes to use:
        // - If the value is between 0-125, the 7 bits in the second byte represent the actual payload length
        // - If the value is 126, the payload length is determined by the following 2 bytes interpreted as a 16-bit unsigned integer
        // - If the value is 127, the payload length is determined by the following 8 bytes interpreted as a 64-bit unsigned integer
        // (The most significant bit must be 0. in all cases, the minimal number of bytes must be used to encode the length)
        rsUInt64 frameIdx            = 2;
        rsUInt64 actualPayloadLength = 0;
        if(tmpPayloadLength == 126) {
            // Bytes 3-4 are used if payloadLength == 126
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
        } else if(tmpPayloadLength == 127) {
            // Bytes 3-10 are used if payloadLength == 127
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
            actualPayloadLength = (actualPayloadLength << 8) | messageBytes[frameIdx++];
        } else {
            actualPayloadLength = tmpPayloadLength;
        }

        // Read the Masking-Key
        // The masking key is a 32-bit value, spanning the next 4 bytes after the payload length
        // (In theory only done if the mask bit is set, but the Client MUST always mask ALL frames, as defined in the RFC)
        rsUInt32 maskingKey = 0;
        if(maskBitSet) {
            maskingKey = (maskingKey << 8) | messageBytes[frameIdx++];
            maskingKey = (maskingKey << 8) | messageBytes[frameIdx++];
            maskingKey = (maskingKey << 8) | messageBytes[frameIdx++];
            maskingKey = (maskingKey << 8) | messageBytes[frameIdx++];
        }

        // Read the Payload Data
        // (In theory divided into "Extension Data" and "Application Data", but extention must be specifically negotiated - Not yet implemented)
        std::vector<rsByte> payloadData(actualPayloadLength);
        for(rsUInt64 i = 0; i < actualPayloadLength; i++) {
            // For each byte in the payload, perform an XOR operation with the corresponding byte from the masking key
            // The masking key is treated as a circular array, hence the use of 'i % 4' to select the next appropriate byte
            payloadData[i] = (messageBytes[frameIdx++] ^ ((maskingKey >> (8 * (3 - i % 4))) & 0xFF));
        }

        return { clientSocketfd, fin, rsv, opc, std::string(payloadData.begin(), payloadData.end()) };
    }

  private:
    const ServerConfig _config;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
