#include "pch.h"
#include "hooks.h"
#include "sync.h"

#ifdef CRYPTER_PLUGIN

namespace {

DWORD WINAPI startup_thread(LPVOID /*unused*/) {
    try {
        b4ac::init_hooks();
        std::cout << "[b4ac] initialized\n" << std::flush;
    } catch (const std::exception& ex) {
        std::cerr << "[b4ac] error while initalizing: " << ex.what() << "\n" << std::flush;
    } catch (...) {
        std::cerr << "[b4ac] unknown error while initalizing\n" << std::flush;
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
