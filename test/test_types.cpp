#define CATCH_CONFIG_MAIN

#include "../src/types.hpp"

#include <catch2/catch_all.hpp>
#include <catch2/catch_user_config.hpp>

TEST_CASE("rs types size", "[rs_types]") {
    using namespace reServ::Common;

    // Basic "rs" type validation - size could be implementation dependent
    REQUIRE(sizeof(rsByte) == 1);
    REQUIRE(sizeof(rsUInt8) == 1);
    REQUIRE(sizeof(rsUInt16) == 2);
    REQUIRE(sizeof(rsUInt32) == 4);
    REQUIRE(sizeof(rsUInt64) == 8);
    // U, UL, ULL suffixes are used in the BIT-MACROS
    REQUIRE(sizeof(1U) == 4);
    REQUIRE(sizeof(1UL) == 8);
}

TEST_CASE("rs types are unsigned", "[rs_types]") {
    using namespace reServ::Common;

    REQUIRE(std::is_unsigned<rsByte>::value);
    REQUIRE(std::is_unsigned<rsUInt8>::value);
    REQUIRE(std::is_unsigned<rsUInt16>::value);
    REQUIRE(std::is_unsigned<rsUInt32>::value);
    REQUIRE(std::is_unsigned<rsUInt64>::value);
    // U, UL, ULL suffixes are used in the BIT-MACROS
    REQUIRE(std::is_unsigned<decltype(1U)>::value);
    REQUIRE(std::is_unsigned<decltype(1UL)>::value);
    REQUIRE(std::is_unsigned<decltype(1ULL)>::value);
}

TEST_CASE("Bit set and clear macros - 1 Byte", "[bit_macros]") {
    using namespace reServ::Common;

    rsByte val = 0b00001010; // Bit 1 and 3 are set

    REQUIRE(IS_BIT_SET_1B(val, 1));
    REQUIRE(IS_BIT_SET_1B(val, 3));
    REQUIRE(IS_BIT_CLEAR_1B(val, 0));
    REQUIRE(IS_BIT_CLEAR_1B(val, 2));
}

TEST_CASE("Bit set and clear macros - 4 Bytes", "[bit_macros]") {
    using namespace reServ::Common;

    rsUInt32 val = 1UL << 24 | 1UL << 26; // Bit 24 and 26 are set

    REQUIRE(IS_BIT_SET_4B(val, 24));
    REQUIRE(IS_BIT_SET_4B(val, 26));
    REQUIRE(IS_BIT_CLEAR_4B(val, 23));
    REQUIRE(IS_BIT_CLEAR_4B(val, 25));
}

TEST_CASE("Bit set and clear macros - 8 Bytes", "[bit_macros]") {
    using namespace reServ::Common;

    rsUInt64 val = 1ULL << 50 | 1ULL << 60; // Bit 50 and 60 are set

    REQUIRE(IS_BIT_SET_8B(val, 50));
    REQUIRE(IS_BIT_SET_8B(val, 60));
    REQUIRE(IS_BIT_CLEAR_8B(val, 49));
    REQUIRE(IS_BIT_CLEAR_8B(val, 59));
}
