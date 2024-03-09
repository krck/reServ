#define CATCH_CONFIG_MAIN

#include "../src/serverMessageHandler.hpp"

#include <catch2/catch_all.hpp>
#include <catch2/catch_user_config.hpp>

TEST_CASE("parseWsMessage function", "[reServ]") {
    SECTION("Test with short length payload") {
        std::vector<uint8_t> message = { 0x81, 0x03, 0x48, 0x65, 0x79 }; // "Hey"
        std::string result           = reServ::parseWsMessage(message);
        REQUIRE(result == "Hey");
    }

    SECTION("Test with medium length payload") {
        std::vector<uint8_t> message = { 0x81, 0x7E, 0x01, 0x00 }; // 256 bytes of 'A'
        for(int i = 0; i < 256; i++) {
            message.push_back('A');
        }
        std::string result = reServ::parseWsMessage(message);
        REQUIRE(result == std::string(256, 'A'));
    }

    SECTION("Test with long length payload") {
        std::vector<uint8_t> message = { 0x81, 0x7F }; // 65536 bytes of 'B'
        for(int i = 0; i < 8; i++) {
            message.push_back(0x01);
        }
        for(int i = 0; i < 65536; i++) {
            message.push_back('B');
        }
        std::string result = reServ::parseWsMessage(message);
        REQUIRE(result == std::string(65536, 'B'));
    }

    SECTION("Test with masked payload") {
        std::vector<uint8_t> message = { 0x81, 0x83, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 }; // "Hello"
        std::string result           = reServ::parseWsMessage(message);
        REQUIRE(result == "Hello");
    }

    SECTION("Test with different WebSocket message types") {
        std::vector<uint8_t> textMessage = { 0x81, 0x03, 0x48, 0x65, 0x79 }; // "Hey"
        std::string textResult           = reServ::parseWsMessage(textMessage);
        REQUIRE(textResult == "Hey");

        std::vector<uint8_t> binaryMessage = { 0x82, 0x03, 0x01, 0x02, 0x03 }; // Binary data
        std::string binaryResult           = reServ::parseWsMessage(binaryMessage);
        REQUIRE(binaryResult == std::string("\x01\x02\x03", 3));
    }
}
