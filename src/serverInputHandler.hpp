#ifndef RESERV_SERVERINPUTHANDLER_H
#define RESERV_SERVERINPUTHANDLER_H

#include "clientMessage.hpp"
#include "closeCondition.hpp"
#include "configService.hpp"
#include "enums.hpp"
#include "logger.hpp"
#include "types.hpp"

#include <string>
#include <variant>
#include <vector>

namespace reServ::Server {

using namespace reServ::Client;
using namespace reServ::Common;

class ServerInputHandler {
  public:
    ServerInputHandler() : _config(ConfigService::instance().getServerConfig()), _logger(Logger::instance()) {}

    ~ServerInputHandler() = default;

  public:
    bool parseFrameLength(const std::vector<rsByte>& buffer) const {
        if(buffer.size() < 2) {
            // Not enough data for the header
            return false;
        }

        rsByte payloadLen = buffer[1] & 0x7F;
        size_t headerSize = 2;
        if(payloadLen == 126) {
            headerSize += 2;
        } else if(payloadLen == 127) {
            headerSize += 8;
        }

        if(buffer.size() < headerSize) {
            // Not enough data for the extended payload length
            return false;
        }

        size_t totalSize = headerSize;
        if(payloadLen == 126) {
            totalSize += (buffer[2] << 8) | buffer[3];
        } else if(payloadLen == 127) {
            for(int i = 0; i < 8; i++) {
                totalSize = (totalSize << 8) | buffer[2 + i];
            }
        } else {
            totalSize += payloadLen;
        }

        // Check if we have enough data for the full frame
        return buffer.size() >= totalSize;
    }

    std::variant<ClientMessage, CloseCondition> parseWsDataFrame(int clientSocketfd, const std::vector<rsByte>& messageBytes) const {
        // Add some logic for "fragmented" messages here
        // WebSocket: Message only ends, when the FIN bit is set (one client can send multiple messages in one packet)
        // ...
        // Caching logic, that stores the last message per "clientSocketfd" and appends the new one to it, if the FIN bit is not set
        // Only if the FIN bit is set, the message is returned to the server, where it is then added to the message queue
        // ...

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
        if(!maskBitSet) {
            // The server MUST close the connection upon receiving a frame with the mask bit set to 0
            // (The client MUST always set the mask bit to 1, as defined in the RFC)
            return CloseCondition { clientSocketfd, true, "Server received a frame with the mask bit set to 0", WsCloseCode::PROTOCOL_ERROR };
        }

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
        maskingKey          = (maskingKey << 8) | messageBytes[frameIdx++];
        maskingKey          = (maskingKey << 8) | messageBytes[frameIdx++];
        maskingKey          = (maskingKey << 8) | messageBytes[frameIdx++];
        maskingKey          = (maskingKey << 8) | messageBytes[frameIdx++];

        // Read the Payload Data
        // (In theory divided into "Extension Data" and "Application Data", but extention must be specifically negotiated - Not yet implemented)
        std::vector<rsByte> payloadData(actualPayloadLength);
        for(rsUInt64 i = 0; i < actualPayloadLength; i++) {
            // For each byte in the payload, perform an XOR operation with the corresponding byte from the masking key
            // The masking key is treated as a circular array, hence the use of 'i % 4' to select the next appropriate byte
            payloadData[i] = (messageBytes[frameIdx++] ^ ((maskingKey >> (8 * (3 - i % 4))) & 0xFF));
        }

        return ClientMessage { clientSocketfd, fin, rsv, opc, payloadData };
    }

  private:
    const ServerConfig _config;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
