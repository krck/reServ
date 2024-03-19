#ifndef RESERV_CLOSECONDITION_H
#define RESERV_CLOSECONDITION_H

#include "enums.hpp"

namespace reServ::Common {

struct CloseCondition {
  public:
    const int clientSocketfd;
    const bool wsConnectionEstablished;
    const std::string closeInfo;
    const WsCloseCode closeCode;

  public:
    CloseCondition(int clientSocketfd, bool wsConnectionEstablished, std::string closeInfo, WsCloseCode closeCode = WsCloseCode::CL_NONE) :
      clientSocketfd(clientSocketfd), wsConnectionEstablished(wsConnectionEstablished), closeInfo(std::move(closeInfo)),
      closeCode((wsConnectionEstablished ? closeCode : WsCloseCode::CL_NONE)) {}

    ~CloseCondition() = default;
};

} // namespace reServ::Common

#endif
