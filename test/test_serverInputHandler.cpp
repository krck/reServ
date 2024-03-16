#define CATCH_CONFIG_MAIN

#include "../src/serverConfig.hpp"
#include "../src/serverInputHandler.hpp"

#include <catch2/catch_all.hpp>
#include <catch2/catch_user_config.hpp>

using namespace reServ::Server;

TEST_CASE("ServerInputHandler tests", "[ServerInputHandler]") {
    ServerInputHandler handler { ServerConfig(/* default config */) };

    SECTION("handleInputData test") {
        std::vector<rsByte> recvBuffer = { /* Add some test data here */ };

        ClientMessage result = handler.handleInputData(1, recvBuffer);

        // Add assertions here based on what you expect the result to be
        // For example, if you expect the result to have a certain property:
        // REQUIRE(result.property == expectedValue);
    }
}
