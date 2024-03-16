#ifndef RESERV_SERVEROUTPUTHANDLER_H
#define RESERV_SERVEROUTPUTHANDLER_H

#include "clientMessage.hpp"
#include "enums.hpp"
#include "logger.hpp"
#include "serverConfig.hpp"
#include "types.hpp"

#include <random>
#include <string>
#include <vector>

namespace reServ::Server {

using namespace reServ::Client;
using namespace reServ::Common;

//
// ServerOutputHandler
//
class ServerOutputHandler {
  public:
    ServerOutputHandler(const ServerConfig& config) : _config(config), _logger(Logger::instance()) {}

    ~ServerOutputHandler() = default;

  public:
    bool handleOutputData(const ClientMessage* const message) const {
        // Add some logic for "split" messages here
        // WebSocket: Message only ends, when the FIN bit is set (one client can send multiple messages in one packet)
        // ...
        // Caching logic, that stores the last message per "clientSocketfd" and appends the new one to it, if the FIN bit is not set
        // Only if the FIN bit is set, the message is returned to the server, where it is then added to the message queue
        // ...
    }

  private:
    std::vector<rsByte> generateWebSocketFrame(bool fin, uint8_t opcode, bool masked, const std::string& payload) {
        std::vector<rsByte> frame;

        // First byte: FIN and opcode
        rsByte firstByte = (fin ? 0x80 : 0x00) | (opcode & 0x0F);
        frame.push_back(firstByte);

        // Second byte: Mask and payload length
        size_t payloadLength = payload.size();
        rsByte secondByte    = (masked ? 0x80 : 0x00);
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
            for(int i = 7; i >= 0; --i) {
                frame.push_back((payloadLength >> (8 * i)) & 0xFF);
            }
        }

        // Masking key
        if(masked) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            for(int i = 0; i < 4; ++i) {
                frame.push_back(dis(gen));
            }
        }

        // Payload
        for(size_t i = 0; i < payloadLength; ++i) {
            frame.push_back(payload[i] ^ (masked ? frame[(i % 4) + 2] : 0));
        }

        return frame;
    }

  private:
    const ServerConfig _config;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
