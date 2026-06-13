#pragma once
#include <cstdint>
#include <xstd/intrinsics.hpp>
#include <xstd/type_helpers.hpp>

// Helper for escaping templates.
//
#define _SDK_ESCAPE(...) __VA_ARGS__

// Find out if we're being evaluated by a code-parser or a compiler.
//
#ifdef __INTELLISENSE__
	#define IN_PARSER 1
#else
	#define IN_PARSER 0
#endif

// Validate compiler.
//
#ifdef __clang__
	#define CLANG_COMPILER 1
#else
	#define CLANG_COMPILER 0
#endif

#if !CLANG_COMPILER
	#ifndef IN_GENERATOR
		#error "SDK can only be used with Clang compatible compilers."
	#endif
#else
	#pragma GCC diagnostic ignored "-Wunused-function"
	#pragma GCC diagnostic ignored "-Wduplicate-decl-specifier"
	#pragma GCC diagnostic ignored "-Wdeprecated-volatile"
	#pragma GCC diagnostic ignored "-Wignored-qualifiers"
	#pragma GCC diagnostic ignored "-Wgnu-string-literal-operator-template"
#endif

// Compiler attribute / builtin shims.  The full runtime path expects a
// patched LLVM toolchain that supplies `__builtin_symbol_read*` and the
// custom `no_split` / `no_stub` attributes; on vanilla clang those slots
// degrade to no-ops + zero-value reads, which is enough to syntax-check
// the generated headers but not to run the patcher's symbol-table
// indirection at link time.
//
#ifndef IN_GENERATOR
	#ifndef FORCE_INLINE
		#define FORCE_INLINE [[gnu::always_inline]] inline
	#endif
	#ifndef CONST_FN
		#define CONST_FN [[gnu::const]]
	#endif
	#if !defined(__has_attribute) || !__has_attribute(no_split)
		#define no_split
	#endif
	#if !defined(__has_attribute) || !__has_attribute(no_stub)
		#define no_stub
	#endif
	// Vanilla-clang fallback for the patched-LLVM symbol-read builtins.
	// Mirrors the patcher's per-field decode: advance the LCG by
	// `byte_offset / 8` steps (one step per qword crossed), shift the
	// derived key right by `byte_offset % 8` bytes for sub-qword
	// alignment, then XOR against the cipher word at `src`.
	//
	#if !__has_builtin(__builtin_symbol_read1)
		[[gnu::const]] inline std::uint64_t __ntbind_symbol_key_at(std::uint64_t key, std::size_t byte_offset)
		{
			for (std::size_t i = 0; i < byte_offset / 8; i++) {
				key = 0x5851F42D4C957F2Dull * key + 0x14057B7EF767814Full;
			}
			return key >> ((byte_offset % 8) * 8);
		}
		[[gnu::const]] inline std::uint8_t __builtin_symbol_read1(
			const volatile void* src, std::size_t offset, std::uint64_t key)
		{
			std::uint8_t cipher;
			__builtin_memcpy(&cipher, const_cast<const void*>(src), sizeof(cipher));
			return static_cast<std::uint8_t>(
				cipher ^ static_cast<std::uint8_t>(__ntbind_symbol_key_at(key, offset)));
		}
		[[gnu::const]] inline std::uint16_t __builtin_symbol_read2(
			const volatile void* src, std::size_t offset, std::uint64_t key)
		{
			std::uint16_t cipher;
			__builtin_memcpy(&cipher, const_cast<const void*>(src), sizeof(cipher));
			return static_cast<std::uint16_t>(
				cipher ^ static_cast<std::uint16_t>(__ntbind_symbol_key_at(key, offset)));
		}
		[[gnu::const]] inline std::uint32_t __builtin_symbol_read4(
			const volatile void* src, std::size_t offset, std::uint64_t key)
		{
			std::uint32_t cipher;
			__builtin_memcpy(&cipher, const_cast<const void*>(src), sizeof(cipher));
			return cipher ^ static_cast<std::uint32_t>(__ntbind_symbol_key_at(key, offset));
		}
		[[gnu::const]] inline std::uint64_t __builtin_symbol_read8(
			const volatile void* src, std::size_t offset, std::uint64_t key)
		{
			std::uint64_t cipher;
			__builtin_memcpy(&cipher, const_cast<const void*>(src), sizeof(cipher));
			return cipher ^ __ntbind_symbol_key_at(key, offset);
		}
	#endif

	// Polymorphic pointer -- accepts any T* and decays back into T* or
	// std::uintptr_t.  Sized identically to `void*` so it can stand in
	// `any_ptr` -- xstd provides this in type_helpers.hpp; the alias
	// brings it into the global namespace where the runtime headers
	// reference it unqualified.
#endif
