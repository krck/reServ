#ifndef RESERV_CLIENTMESSAGE_H
#define RESERV_CLIENTMESSAGE_H

#include "enums.hpp"

#include <string>
#include <sys/socket.h>
#include <vector>

namespace reServ::Client {

using namespace reServ::Common;

struct ClientMessage {
  public:
    const int clientSocketfd;
    const WsFrame_FIN fin;
    const WsFrame_RSV rsv;
    const WsFrame_OPC opc; // OpCode
    const rsUInt32 maskingKey;

  public:
    ClientMessage(int clientSocketfd, WsFrame_FIN fin, WsFrame_RSV rsv, WsFrame_OPC opc, rsUInt32 maskingKey, rsUInt64 fullPayloadLength) :
      clientSocketfd(clientSocketfd), fin(fin), rsv(rsv), opc(opc), maskingKey(maskingKey), _fullPayloadLength(fullPayloadLength) {}

    ~ClientMessage() = default;

  public:
    bool isReceived() const { return (_fullPayloadLength == _payloadData.size()); }
    rsUInt64 remaining() const { return _fullPayloadLength - _payloadData.size(); }
    rsUInt64 size() const { return _payloadData.size(); }

    void appendPayload(const std::vector<rsByte>& data) {
        _payloadData.reserve(_payloadData.size() + data.size());
        _payloadData.insert(_payloadData.end(), data.begin(), data.end());
    }

    const std::vector<rsByte>& getPayload() const { return _payloadData; }

  private:
    const rsUInt64 _fullPayloadLength;
    std::vector<rsByte> _payloadData;
    // std::string(payloadData.begin(), payloadData.end())
};

} // namespace reServ::Client

#endif
