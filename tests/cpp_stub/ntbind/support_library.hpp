// Parser-mode stub of support_library.hpp.  Defines only the macros and
// helper types the generated headers reference so clang -fsyntax-only can
// check the C++ SDK without pulling in the runtime's external
// dependencies.

#pragma once

#include <stdint.h>
#include <stddef.h>

#define IN_PARSER 1
#define IN_GENERATOR 1
#define _SDK_ESCAPE(...) __VA_ARGS__

#define SDK_MAGIC_PROPERTIES(name, size, exists, key) /* no-op */
#define SDK_FIXED_SIZE(T, size) char _raw[size] = {};
#define SDK_VERIFY(...)         /* no-op */

namespace sdk {
    template<typename T, size_t N> struct array { T data[N]; };
    struct unknown_ptr { uint64_t ptr; };
}
namespace nt {
    struct list_entry_t { void* flink; void* blink; };
    struct unicode_view { uint16_t length; uint16_t maximum_length; uint16_t* buffer; };
    struct unicode_view32 { uint16_t length; uint16_t maximum_length; uint32_t buffer; };
    struct ascii_view { uint16_t length; uint16_t maximum_length; uint8_t* buffer; };
    struct ascii_view32 { uint16_t length; uint16_t maximum_length; uint32_t buffer; };
    struct trapframe { uint8_t _raw[0x190]; };
    struct context { uint8_t _raw[0x4d0]; };
    struct xsave_format { uint8_t _raw[0x200]; };
    struct exframe { uint8_t _raw[0x140]; };
}
struct m128a_t { uint64_t low; int64_t high; };

#define NTBIND_BIT_T(n, base) using uint##n##_t = base; using int##n##_t = base;
NTBIND_BIT_T(1, uint8_t) NTBIND_BIT_T(2, uint8_t) NTBIND_BIT_T(3, uint8_t)
NTBIND_BIT_T(4, uint8_t) NTBIND_BIT_T(5, uint8_t) NTBIND_BIT_T(6, uint8_t)
NTBIND_BIT_T(7, uint8_t) NTBIND_BIT_T(9, uint16_t) NTBIND_BIT_T(10, uint16_t)
NTBIND_BIT_T(11, uint16_t) NTBIND_BIT_T(12, uint16_t) NTBIND_BIT_T(13, uint16_t)
NTBIND_BIT_T(14, uint16_t) NTBIND_BIT_T(15, uint16_t) NTBIND_BIT_T(17, uint32_t)
NTBIND_BIT_T(18, uint32_t) NTBIND_BIT_T(19, uint32_t) NTBIND_BIT_T(20, uint32_t)
NTBIND_BIT_T(21, uint32_t) NTBIND_BIT_T(22, uint32_t) NTBIND_BIT_T(23, uint32_t)
NTBIND_BIT_T(24, uint32_t) NTBIND_BIT_T(25, uint32_t) NTBIND_BIT_T(26, uint32_t)
NTBIND_BIT_T(27, uint32_t) NTBIND_BIT_T(28, uint32_t) NTBIND_BIT_T(29, uint32_t)
NTBIND_BIT_T(30, uint32_t) NTBIND_BIT_T(31, uint32_t) NTBIND_BIT_T(33, uint64_t)
NTBIND_BIT_T(34, uint64_t) NTBIND_BIT_T(35, uint64_t) NTBIND_BIT_T(36, uint64_t)
NTBIND_BIT_T(37, uint64_t) NTBIND_BIT_T(38, uint64_t) NTBIND_BIT_T(39, uint64_t)
NTBIND_BIT_T(40, uint64_t) NTBIND_BIT_T(41, uint64_t) NTBIND_BIT_T(42, uint64_t)
NTBIND_BIT_T(43, uint64_t) NTBIND_BIT_T(44, uint64_t) NTBIND_BIT_T(45, uint64_t)
NTBIND_BIT_T(46, uint64_t) NTBIND_BIT_T(47, uint64_t) NTBIND_BIT_T(48, uint64_t)
NTBIND_BIT_T(49, uint64_t) NTBIND_BIT_T(50, uint64_t) NTBIND_BIT_T(51, uint64_t)
NTBIND_BIT_T(52, uint64_t) NTBIND_BIT_T(53, uint64_t) NTBIND_BIT_T(54, uint64_t)
NTBIND_BIT_T(55, uint64_t) NTBIND_BIT_T(56, uint64_t) NTBIND_BIT_T(57, uint64_t)
NTBIND_BIT_T(58, uint64_t) NTBIND_BIT_T(59, uint64_t) NTBIND_BIT_T(60, uint64_t)
NTBIND_BIT_T(61, uint64_t) NTBIND_BIT_T(62, uint64_t) NTBIND_BIT_T(63, uint64_t)

struct nop_t {};
