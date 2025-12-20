#include "pch.h"
#include "hooks.h"
#include "logging.h"
#include "sync.h"

#ifdef CRYPTER_PLUGIN

namespace {

DWORD WINAPI startup_thread(LPVOID /*unused*/) {
    try {
        b4ac::start_syncing_thread();
        b4ac::init_hooks();
        b4ac::log::info("initialized");
    } catch (const std::exception& ex) {
        b4ac::log::error("error while initalizing: {}", ex.what());
    } catch (...) {
        b4ac::log::error("unknown error while initalizing");
    }
    return 1;
}

}  // namespace

// NOLINTNEXTLINE(misc-use-internal-linkage, readability-identifier-naming)
BOOL APIENTRY DllMain(HMODULE h_module, DWORD ul_reason_for_call, LPVOID /*unused*/) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(h_module);
            CreateThread(nullptr, 0, &startup_thread, nullptr, 0, nullptr);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

#endif
