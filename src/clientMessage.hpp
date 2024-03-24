#ifndef RESERV_CLIENTMESSAGE_H
#define RESERV_CLIENTMESSAGE_H

#include "enums.hpp"

#include <string>
#include <sys/socket.h>
#include <vector>

namespace reServ::Client {

using namespace reServ::Common;

class Message {
  public:
    const int clientSocketfd;
    const OutputMethod outputMethod;

  public:
    virtual ~Message() = default;

    inline rsUInt64 size() const { return _payloadData.size(); }
    inline bool isReceived() const { return (_fullPayloadLength == _payloadData.size()); }
    inline rsUInt64 remaining() const { return _fullPayloadLength - _payloadData.size(); }

    void appendPayload(const std::vector<rsByte>& data) {
        _payloadData.reserve(_payloadData.size() + data.size());
        _payloadData.insert(_payloadData.end(), data.begin(), data.end());
    }

    const std::vector<rsByte>& getPayload() const { return _payloadData; }

  protected:
    Message(int clientSocketfd, rsUInt64 fullPayloadLength, OutputMethod outputMethod) :
      clientSocketfd(clientSocketfd), outputMethod(outputMethod), _fullPayloadLength(fullPayloadLength), _payloadData({}) {}

    Message(int clientSocketfd, rsUInt64 fullPayloadLength, OutputMethod outputMethod, const std::vector<rsByte>& payloadData) :
      clientSocketfd(clientSocketfd), outputMethod(outputMethod), _fullPayloadLength(fullPayloadLength), _payloadData(payloadData) {}

  protected:
    const rsUInt64 _fullPayloadLength;
    std::vector<rsByte> _payloadData;
};

class WebSocketMessage : public Message {
  public:
    const WsFrame_FIN fin;
    const WsFrame_RSV rsv;
    const WsFrame_OPC opc; // OpCode
    const rsUInt32 maskingKey;

  public:
    WebSocketMessage(int clientSocketfd, WsFrame_FIN fin, WsFrame_RSV rsv, WsFrame_OPC opc, rsUInt32 maskingKey, rsUInt64 fullPayloadLength,
                     OutputMethod outputMethod) :
      Message(clientSocketfd, fullPayloadLength, outputMethod),
      fin(fin), rsv(rsv), opc(opc), maskingKey(maskingKey) {}

    ~WebSocketMessage() = default;
};

} // namespace reServ::Client

#endif
