#ifndef RESERV_CLOSECONDITION_H
#define RESERV_CLOSECONDITION_H

#include "enums.hpp"

namespace reServ::Common {

struct CloseCondition {
  public:
    const int clientSocketfd;
    const bool wsConnectionEstablished;
    const WsCloseCode closeCode;

  public:
    CloseCondition(int clientSocketfd, bool wsConnectionEstablished, WsCloseCode closeCode) :
      clientSocketfd(clientSocketfd), wsConnectionEstablished(wsConnectionEstablished), closeCode(closeCode) {}

    ~CloseCondition() = default;
};

} // namespace reServ::Common

#endif
