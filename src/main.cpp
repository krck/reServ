#include "configService.hpp"
#include "server.hpp"

using namespace reServ::Server;
using namespace reServ::Common;

int main(int argc, char* argv[]) {
    // Try to update the server configuration from the command-line arguments
    ConfigService::instance().updateServerConfigFromArgs(argc, argv);

    // Start and run the server
    Logger::instance().log(LogLevel::Info, "Server config valid. Starting...");
    Server tcpServer;
    return tcpServer.run();
}
