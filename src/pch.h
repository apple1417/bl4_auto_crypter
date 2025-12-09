#ifndef PCH_H
#define PCH_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
// must be after windows.h
#include <shlobj.h>
#include <wincrypt.h>

#include <MinHook.h>
#include <zlib.h>

#ifdef __cplusplus
#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <limits>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using std::int16_t;
using std::int32_t;
using std::int64_t;
using std::int8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::uint8_t;

#endif

// define to add a bunch of extra log messages
#undef B4AC_DEBUG_LOGGING

#ifdef __MINGW32__
#define BCRYPT_SHA1_ALG_HANDLE ((BCRYPT_ALG_HANDLE)0x00000031)
#define BCRYPT_AES_ECB_ALG_HANDLE ((BCRYPT_ALG_HANDLE)0x000001b1)
#endif

#endif /* PCH_H */
