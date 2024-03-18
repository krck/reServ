#ifndef RESERV_CLOSECONDITION_H
#define RESERV_CLOSECONDITION_H

#include "enums.hpp"

namespace reServ::Common {

struct CloseCondition {
  public:
    int clientSocketfd;
    WsCloseCode closeCode;

  public:
    CloseCondition(int clientSocketfd, WsCloseCode closeCode) : clientSocketfd(clientSocketfd), closeCode(closeCode) {}

    ~CloseCondition() = default;
};

} // namespace reServ::Common

#endif
