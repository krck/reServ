#ifndef RESERV_SERVER_MESSAGEHANDLER_H
#define RESERV_SERVER_MESSAGEHANDLER_H

#include <string>
#include <vector>

namespace reServ::Server {

std::string parseWsMessage(const std::vector<uint8_t>& message) {
    size_t index        = 0;
    uint8_t finNopcode  = message[index++];
    uint8_t maskNlength = message[index++];

    uint64_t payloadLength = maskNlength & 0x7F;
    if(payloadLength == 126) {
        payloadLength = (message[index++] << 8) | message[index++];
    } else if(payloadLength == 127) {
        payloadLength = 0;
        for(int i = 0; i < 8; i++) {
            payloadLength = (payloadLength << 8) | message[index++];
        }
    }

    std::vector<uint8_t> maskingKey;
    if(maskNlength & 0x80) {
        for(int i = 0; i < 4; i++) {
            maskingKey.push_back(message[index++]);
        }
    }

    std::vector<uint8_t> payloadData(payloadLength);
    for(uint64_t i = 0; i < payloadLength; i++) {
        payloadData[i] = message[index++];
        if(!maskingKey.empty()) {
            payloadData[i] ^= maskingKey[i % 4];
        }
    }

    return std::string(payloadData.begin(), payloadData.end());
}

} // namespace reServ::Server

#endif
