#include "pch.h"
#include "logging.h"

namespace b4ac::log {

#ifdef B4AC_LOG_TO_FILE

namespace {

std::filesystem::path get_log_file_path(void) {
    HMODULE this_module = nullptr;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&get_log_file_path), &this_module)
        == 0) {
        return "bl4_auto_crypter.log";
    }

    wchar_t buf[MAX_PATH];
    auto num_chars = GetModuleFileNameW(this_module, &buf[0], ARRAYSIZE(buf));
    if (num_chars == 0) {
        return "bl4_auto_crypter.log";
    }

    auto begin = &buf[0];
    const std::filesystem::path this_module_path{begin, begin + num_chars};
    return this_module_path.parent_path() / "bl4_auto_crypter.log";
}

}  // namespace

std::ofstream log_file_stream{get_log_file_path(), std::ofstream::app};

#endif

}  // namespace b4ac::log
