#ifndef RESERV_CLIENTMESSAGE_H
#define RESERV_CLIENTMESSAGE_H

#include "enums.hpp"

#include <string>
#include <sys/socket.h>

namespace reServ::Client {

using namespace reServ::Common;

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

} // namespace reServ::Client

#endif
