#define CATCH_CONFIG_MAIN

#include "../src/configService.hpp"

#include <catch2/catch_all.hpp>
#include <catch2/catch_user_config.hpp>

TEST_CASE("ConfigService updates server configuration correctly", "[ConfigService]") {
    using namespace reServ::Common;
    ConfigService& configService = ConfigService::instance();

    SECTION("Update port") {
        char* argv[]          = { (char*)"reServ", (char*)"--port", (char*)"9001" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.port == 9001);
    }

    SECTION("Update port") {
        char* argv[]          = { (char*)"reServ", (char*)"--p", (char*)"9002" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.port == 9002);
    }

    SECTION("Update wsVersion") {
        char* argv[]          = { (char*)"reServ", (char*)"--wsVersion", (char*)"any" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.wsVersion == "any");
    }

    SECTION("Update v") {
        char* argv[]          = { (char*)"reServ", (char*)"--v", (char*)"any2" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.wsVersion == "any2");
    }

    SECTION("Update maxConnectionBacklog") {
        char* argv[]          = { (char*)"reServ", (char*)"--maxConnectionBacklog", (char*)"99" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.maxConnectionBacklog == 99);
    }

    SECTION("Update maxEpollEvents") {
        char* argv[]          = { (char*)"reServ", (char*)"--maxEpollEvents", (char*)"99" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.maxEpollEvents == 99);
    }

    SECTION("Update maxPayloadLength") {
        char* argv[]          = { (char*)"reServ", (char*)"--maxPayloadLength", (char*)"99" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.maxPayloadLength == 99);
    }

    SECTION("Update idleTimeout") {
        char* argv[]          = { (char*)"reServ", (char*)"--idleTimeout", (char*)"99" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.idleTimeout == 99);
    }

    SECTION("Update compression") {
        char* argv[]          = { (char*)"reServ", (char*)"--compression", (char*)"99" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.compression == 99);
    }

    SECTION("Update closeOnBackPressureLimit") {
        char* argv[]          = { (char*)"reServ", (char*)"--closeOnBackPressureLimit", (char*)"1" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.closeOnBackPressureLimit == true);
    }

    SECTION("Update resetIdleTimeoutOnSend") {
        char* argv[]          = { (char*)"reServ", (char*)"--resetIdleTimeoutOnSend", (char*)"1" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.resetIdleTimeoutOnSend == true);
    }

    SECTION("Update sendPingsAutomatically") {
        char* argv[]          = { (char*)"reServ", (char*)"--sendPingsAutomatically", (char*)"1" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.sendPingsAutomatically == true);
    }

    SECTION("Update outputBehavior") {
        char* argv[]          = { (char*)"reServ", (char*)"--outputBehavior", (char*)"1" };
        const auto& tmpConfig = configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(tmpConfig.outputMethod == OutputMethod::Broadcast);
    }
}

TEST_CASE("ConfigService handles faulty configuration correctly", "[ConfigService]") {
    using namespace reServ::Common;
    ConfigService& configService     = ConfigService::instance();
    const ServerConfig& serverConfig = configService.getServerConfig();

    SECTION("Invalid inputs do not affect server configuration") {
        ServerConfig oldConfig = serverConfig;

        char* argv[] = { (char*)"reServ", (char*)"--invalidArg", (char*)"invalidValue" };
        configService.updateServerConfigFromArgs(3, argv);
        REQUIRE(serverConfig.port == oldConfig.port);
        REQUIRE(serverConfig.wsVersion == oldConfig.wsVersion);
        REQUIRE(serverConfig.maxConnectionBacklog == oldConfig.maxConnectionBacklog);
        REQUIRE(serverConfig.maxEpollEvents == oldConfig.maxEpollEvents);
        REQUIRE(serverConfig.maxPayloadLength == oldConfig.maxPayloadLength);
        REQUIRE(serverConfig.idleTimeout == oldConfig.idleTimeout);
        REQUIRE(serverConfig.compression == oldConfig.compression);
        REQUIRE(serverConfig.closeOnBackPressureLimit == oldConfig.closeOnBackPressureLimit);
        REQUIRE(serverConfig.resetIdleTimeoutOnSend == oldConfig.resetIdleTimeoutOnSend);
        REQUIRE(serverConfig.sendPingsAutomatically == oldConfig.sendPingsAutomatically);
        REQUIRE(serverConfig.outputMethod == oldConfig.outputMethod);

        char* argv2[] = { (char*)"reServ", (char*)"--port", (char*)"invalidValue" };
        configService.updateServerConfigFromArgs(3, argv2);
        REQUIRE(serverConfig.port == oldConfig.port);
    }
}
