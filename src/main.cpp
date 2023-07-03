#include "server.hpp"

using namespace reServ;

int main() {
    Server tcpServer(8080);
    return tcpServer.run();
}
