#ifndef RESERV_SERVEROUTPUTHANDLER_H
#define RESERV_SERVEROUTPUTHANDLER_H

#include "clientConnection.hpp"
#include "clientMessage.hpp"
#include "configService.hpp"
#include "enums.hpp"
#include "logger.hpp"
#include "types.hpp"

#include <memory>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

namespace reServ::Server {

using namespace reServ::Client;
using namespace reServ::Common;

//
// ServerOutputHandler
//
class ServerOutputHandler {
  public:
    ServerOutputHandler() : _config(ConfigService::instance().getServerConfig()), _logger(Logger::instance()) {}

    ~ServerOutputHandler() = default;

  public:
    std::vector<rsByte> handleOutputData(const ClientMessage* const message) const {
        // Add some logic for "fragmented" messages here
        // ...

        if(message->opc == WsFrame_OPC::CLOSE) {
            // Close the connection
            // (for now, hardcoded to 1000: Normal Closure)
            return generateWsCloseFrame(1000);
        }

        return generateWsDataFrame(message->fin, message->opc, message->payloadData);
    }

  private:
    std::vector<rsByte> generateWsDataFrame(WsFrame_FIN fin, WsFrame_OPC opcode, const std::vector<rsByte>& payload) const {
        std::vector<rsByte> frame;
        frame.reserve(payload.size() + _config.frameHeaderSize);

        // The first BYTE contains the FIN bit, RSV1, RSV2, RSV3, and the OP-Code
        // |7|6|5|4|3|2|1|0|
        // |F|R|R|R| opcode|
        // (Mask the OPC with 0x0F to set only the last 4 bits and OR that with fin which sets the first bit)
        rsByte firstByte = ((fin) | (opcode & 0x0F));
        frame.push_back(firstByte);

        // Second byte: Mask and payload length
        const size_t payloadLength = payload.size();
        rsByte secondByte          = 0x00;
        if(payloadLength <= 125) {
            secondByte |= payloadLength;
            frame.push_back(secondByte);
        } else if(payloadLength <= 65535) {
            secondByte |= 126;
            frame.push_back(secondByte);
            frame.push_back((payloadLength >> 8) & 0xFF);
            frame.push_back(payloadLength & 0xFF);
        } else {
            secondByte |= 127;
            frame.push_back(secondByte);
            frame.push_back((payloadLength >> 56) & 0xFF);
            frame.push_back((payloadLength >> 48) & 0xFF);
            frame.push_back((payloadLength >> 40) & 0xFF);
            frame.push_back((payloadLength >> 32) & 0xFF);
            frame.push_back((payloadLength >> 24) & 0xFF);
            frame.push_back((payloadLength >> 16) & 0xFF);
            frame.push_back((payloadLength >> 8) & 0xFF);
            frame.push_back(payloadLength & 0xFF);
        }

        frame.insert(frame.end(), payload.begin(), payload.end());
        return frame;
    }

    std::vector<rsByte> generateWsCloseFrame(rsUInt16 statusCode) const {
        std::vector<rsByte> frame;
        frame.reserve(_config.frameHeaderSize + 2); // 2 bytes for the status code

        // The first BYTE contains the FIN bit, RSV1, RSV2, RSV3, and the OP-Code
        // (Mask the OPC with 0x0F to set only the last 4 bits and OR that with fin which sets the first bit)
        rsByte firstByte = ((WsFrame_FIN::FINAL_FRAME) | (WsFrame_OPC::CLOSE & 0x0F));
        frame.push_back(firstByte);

        // Second byte: Mask and payload length
        rsByte secondByte = 0x00;
        secondByte |= 2; // Payload length is 2 bytes (status code)
        frame.push_back(secondByte);

        // Add the status code to the frame
        frame.push_back((statusCode >> 8) & 0xFF); // High byte
        frame.push_back(statusCode & 0xFF);        // Low byte

        return frame;
    }

  private:
    const ServerConfig _config;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
