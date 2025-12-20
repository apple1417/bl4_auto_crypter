#include "pch.h"
#include "hooks.h"
#include "memory.h"
#include "sync.h"

namespace b4ac {

namespace {

#ifdef B4AC_DEBUG_LOGGING
struct Logger {
    const char* name{};

    Logger(const char* name) : name(name) {
        std::cout << "[b4ac] " << this->name << " enter\n" << std::flush;
    }
    ~Logger(void) { std::cout << "[b4ac] " << this->name << " exit\n" << std::flush; }

    Logger(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger& operator=(Logger&&) = delete;
};
#endif

}  // namespace

#pragma region save file
namespace {

// This hook triggers near simultaneously on multiple threads, and I don't think it likes being
// delayed too long. Since timing isn't critical, we'll just do the actual processing in a thread.

std::atomic_flag syncing_finished;

[[noreturn]] void syncing_thread(void) {
    SetThreadDescription(GetCurrentThread(), L"b4ac syncer");

    while (true) {
        // Wait until the flag is no longer true
        syncing_finished.wait(true);

        // We almost always get a save and profile file save at essentially the same time
        // Wait a little more to try let them both fire before we bother syncing
        // NOLINTNEXTLINE(readability-magic-numbers)
        std::this_thread::sleep_for(std::chrono::milliseconds{50});

        // Set the flag to true, and if it was previously false
        while (!syncing_finished.test_and_set()) {
            // Then it's time to try sync saves
            try {
#ifdef B4AC_DEBUG_LOGGING
                std::cout << "[b4ac] syncing...\n" << std::flush;
#endif

                sync_all_saves();
            } catch (const std::exception& ex) {
                std::cerr << std::format("[b4ac] error while syncing saves: {}\n", ex.what())
                          << std::flush;
            } catch (...) {
                std::cerr << "[b4ac] unknown error while syncing saves\n" << std::flush;
            }

            // While we're syncing, another thread might save a new file and clear the flag
        }
    }
}

struct FString {
    wchar_t* str;
    int32_t count;
    int32_t max;
};

using save_file_func = uint64_t(void* param_1, const FString* file_stem, void* param_3);
save_file_func* save_file_ptr;

// Find this sig by looking for L"%s.tmp" refs - NOT "%s.%s.tmp"
// It should call ReplaceFileW (and a couple other filesystem funcs) near the bottom
const constinit Pattern<44> SAVE_FILE_SIG{
    "41 57"                // push r15
    "41 56"                // push r14
    "41 55"                // push r13
    "41 54"                // push r12
    "56"                   // push rsi
    "57"                   // push rdi
    "55"                   // push rbp
    "53"                   // push rbx
    "48 81 EC ????????"    // sub rsp,000000E8
    "0F29 BC 24 ????????"  // movaps [rsp+000000D0], xmm7
    "0F29 B4 24 ????????"  // movaps [rsp+000000C0], xmm6
    "4D 89 C6"             // mov r14, r8
    "48 89 D3"             // mov rbx, rdx
    "48 89 CF"             // mov rdi, rcx
};

uint64_t save_file_hook(void* param_1, const FString* file_stem, void* param_3) {
    try {
#ifdef B4AC_DEBUG_LOGGING
    // Technically we ought to put this in a try-catch too, but meh
        const Logger log{"save file"};
                              std::wstring_view{file_stem->str, (size_t)file_stem->count},
                              std::this_thread::get_id())
               << std::flush;
#endif

    auto ret = save_file_ptr(param_1, file_stem, param_3);

    try {
        syncing_finished.clear();
        syncing_finished.notify_all();
    } catch (const std::exception& ex) {
        std::cerr << std::format("[b4ac] error in save file hook: {}\n", ex.what()) << std::flush;
    } catch (...) {
        std::cerr << "[b4ac] unknown error in save file hook\n" << std::flush;
    }

    return ret;
}
static_assert(std::is_same_v<decltype(save_file_hook), save_file_func>);

}  // namespace
#pragma endregion

#pragma region delete character
namespace {

using delete_character_func = bool(void* param_1, wchar_t* save_file);
delete_character_func* delete_character_ptr;

// Find this by breakpointing on DeleteFileW, deleting a character, then going up one on the stack
const constinit Pattern<68> DELETE_CHARACTER_SIG{
    "56"                    // push rsi
    "57"                    // push rdi
    "48 81 EC ????????"     // sub rsp, 00000248
    "48 8B 05 ????????"     // mov rax, [Borderlands4.exe+C372940]
    "48 31 E0"              // xor rax, rsp
    "48 89 84 24 ????????"  // mov [rsp+00000240], rax
    "48 8D 7C 24 ??"        // lea rdi, [rsp+20]
    "48 89 F9"              // mov rcx, rdi
    "E8 ????????"           // call Borderlands4.exe+5ADE6C
    "48 8B 47 08"           // mov rax, [rdi+08]
    "66 C7 00 0000"         // mov word ptr [rax], 0000
    "48 8B 0F"              // mov rcx, [rdi]
    "FF 15 ????????"  // call qword ptr [Borderlands4.exe+BBC7C18] { ->->KERNELBASE.DeleteFileW }
    "89 C6"           // mov esi, eax
    "80 7F 18 01"     // cmp byte ptr [rdi+18], 01
    "74 ??"           // je Borderlands4.exe+5C8E8AF
    "85 F6"           // test esi, esi
};

bool delete_character_hook(void* param_1, wchar_t* save_file) {
    try {
#ifdef B4AC_DEBUG_LOGGING
        const Logger log{"delete character"};
#endif

        const std::filesystem::path sav = save_file;
        if (sav.extension() == ".sav") {
            const auto yaml = std::filesystem::path{sav}.replace_extension(".yaml");

            // If we're trying to delete a save which has an equivalent yaml
            if (std::filesystem::exists(sav) && std::filesystem::exists(yaml)) {
                auto ret = delete_character_ptr(param_1, save_file);

                try {
                    // If it truly did remove the save, remove the yaml too
                    if (!std::filesystem::exists(sav)) {
                        std::filesystem::remove(yaml);
                    }
                } catch (const std::exception& ex) {
                    std::cerr << "[b4ac] error in delete character hook: " << ex.what() << "\n"
                              << std::flush;
                } catch (...) {
                    std::cerr << "[b4ac] unknown error in delete character hook\n" << std::flush;
                }

                return ret;
            }
        }

    } catch (const std::exception& ex) {
        std::cerr << "[b4ac] error in delete character hook: " << ex.what() << "\n" << std::flush;
    } catch (...) {
        std::cerr << "[b4ac] unknown error in delete character hook\n" << std::flush;
    }

    return delete_character_ptr(param_1, save_file);
}
static_assert(std::is_same_v<decltype(delete_character_hook), delete_character_func>);

}  // namespace
#pragma endregion

void init_hooks(void) {
    // HACK: since the game is packed, we can't necessarily sigscan until it's been unpacked.
    //       I don't have a good hook for when this is, so just wait it out.
    const constexpr auto sleep_time = std::chrono::seconds{5};
    std::this_thread::sleep_for(sleep_time);

    // Since the flag is clear, first run will do an inital sync
    std::thread(syncing_thread).detach();

    detour(SAVE_FILE_SIG, save_file_hook, &save_file_ptr, "save file");
    detour(DELETE_CHARACTER_SIG, delete_character_hook, &delete_character_ptr, "delete character");
}

}  // namespace b4ac
