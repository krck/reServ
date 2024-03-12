#ifndef RESERV_SERVER_INPUTHANDLER_H
#define RESERV_SERVER_INPUTHANDLER_H

#include "logger.hpp"
#include "serverConfig.hpp"
#include "types.hpp"

#include <string>
#include <vector>

namespace reServ::Server {

using namespace reServ::Common;

class ServerInputHandler {
  public:
    ServerInputHandler(const ServerConfig& config) : _config(config), _logger(Logger::instance()) {}

    ~ServerInputHandler() = default;

  public:
    std::string handleInputData(int clientSocketfd, const std::vector<rsByte>& recvBuffer) const {
        // Add some logic for "split" messages here
        // WebSocket: Message only ends, when the FIN bit is set (one client can send multiple messages in one packet)
        // ...
        // Caching logic, that stores the last message per "clientSocketfd" and appends the new one to it, if the FIN bit is not set
        // Only if the FIN bit is set, the message is returned to the server, where it is then added to the message queue
        // ...

        return parseWsMessage(recvBuffer);
    }

  private:
    std::string parseWsMessage(const std::vector<rsByte>& message) const {
        // ----------------------------------------------------------------------------------------------------------------
        // ---------------------------------------- Parse WebSocket Protocol Data -----------------------------------------
        // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#exchanging_data_frames
        // ----------------------------------------------------------------------------------------------------------------

        size_t index       = 0;
        rsByte finNopcode  = message[index++];
        rsByte maskNlength = message[index++];

        uint64_t payloadLength = maskNlength & 0x7F;
        if(payloadLength == 126) {
            payloadLength = (message[index++] << 8) | message[index++];
        } else if(payloadLength == 127) {
            payloadLength = 0;
            for(int i = 0; i < 8; i++) {
                payloadLength = (payloadLength << 8) | message[index++];
            }
        }

        std::vector<rsByte> maskingKey;
        if(maskNlength & 0x80) {
            maskingKey.push_back(message[index++]);
            maskingKey.push_back(message[index++]);
            maskingKey.push_back(message[index++]);
            maskingKey.push_back(message[index++]);
        }

        std::vector<rsByte> payloadData(payloadLength);
        for(uint64_t i = 0; i < payloadLength; i++) {
            payloadData[i] = message[index++];
            if(!maskingKey.empty()) {
                payloadData[i] ^= maskingKey[i % 4];
            }
        }

        return std::string(payloadData.begin(), payloadData.end());
    }

  private:
    const ServerConfig _config;
    Logger& _logger;
};

} // namespace reServ::Server

#endif
