#define CATCH_CONFIG_MAIN

#include "../src/types.hpp"

#include <catch2/catch_all.hpp>
#include <catch2/catch_user_config.hpp>

TEST_CASE("rsByte size is exactly 1 Byte", "[types]") { REQUIRE(sizeof(uint8_t) == 1); }
TEST_CASE("rsByte is an unsigned integer", "[types]") { REQUIRE(std::is_unsigned<reServ::Common::rsByte>::value); }
