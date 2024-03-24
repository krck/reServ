#ifndef RESERV_TYPES_H
#define RESERV_TYPES_H

#include <cstdint>

namespace reServ::Common {

using rsSocketFd = int;

using rsByte   = std::uint8_t;
using rsUInt8  = std::uint8_t;
using rsUInt16 = std::uint16_t;
using rsUInt32 = std::uint32_t;
using rsUInt64 = std::uint64_t;

using rsInt8  = std::int8_t;
using rsInt16 = std::int16_t;
using rsInt32 = std::int32_t;
using rsInt64 = std::int64_t;

// -------------------------------------------------------------
// ---------------------- BIT READ MACROS ----------------------
// -------------------------------------------------------------
// For 1 byte (8 bits)
#define IS_BIT_SET_1B(val, bit)   ((val) & (1U << (bit)))
#define IS_BIT_CLEAR_1B(val, bit) (!((val) & (1U << (bit))))
// For 4 bytes (32 bits)
#define IS_BIT_SET_4B(val, bit)   ((val) & (1UL << (bit)))
#define IS_BIT_CLEAR_4B(val, bit) (!((val) & (1UL << (bit))))
// For 8 bytes (64 bits)
#define IS_BIT_SET_8B(val, bit)   ((val) & (1ULL << (bit)))
#define IS_BIT_CLEAR_8B(val, bit) (!((val) & (1ULL << (bit))))

} // namespace reServ::Common

#endif
