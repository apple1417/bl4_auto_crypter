#include "pch.h"
#include "hooks.h"
#include "logging.h"
#include "memory.h"
#include "sync.h"

namespace b4ac {

namespace {

#ifdef B4AC_DEBUG_LOGGING
struct Logger {
    const char* name{};

    Logger(const char* name) : name(name) { log::debug("{} enter", this->name); }
    ~Logger(void) { log::debug("{} exit", this->name); }

    Logger(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger& operator=(Logger&&) = delete;
};
#endif

}  // namespace

#pragma region save file
namespace {

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
    "48 81 EC ????????"    // sub rsp, 000000E8
    "0F29 B? 24 ????????"  // movaps [rsp+000000D0] ,xmm7
    "0F29 B? 24 ????????"  // movaps [rsp+000000C0] ,xmm6
    "4D 89 C6"             // mov r14, r8
    "48 89 D?"             // mov rbx, rdx      | mov rdi, rdx
    "48 89 C?"             // mov rdi, rcx      | mov rsi, rcx
};

uint64_t save_file_hook(void* param_1, const FString* file_stem, void* param_3) {
#ifdef B4AC_DEBUG_LOGGING
    // Technically we ought to put this in a try-catch too, but meh
    const Logger log{"save file"};
    // Do this manually so we don't need to convert wstrings
    std::wcout << std::format(L"[b4ac] file: {} thread: {}\n",
                              std::wstring_view{file_stem->str, (size_t)file_stem->count},
                              std::this_thread::get_id())
               << std::flush;
#endif

    auto ret = save_file_ptr(param_1, file_stem, param_3);

    try {
        trigger_sync();
    } catch (const std::exception& ex) {
        log::error("error in save file hook: {}", ex.what());
    } catch (...) {
        log::error("unknown error in save file hook");
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
const constinit Pattern<275> DELETE_CHARACTER_SIG{
    "41 56"                 // push r14
    "56"                    // push rsi
    "57"                    // push rdi
    "53"                    // push rbx
    "48 81 EC ????????"     // sub rsp ,00000248
    "48 8B 05 ????????"     // mov rax, [Borderlands4.exe+11399940]
    "48 31 E0"              // xor rax, rsp
    "48 89 84 24 ????????"  // mov [rsp+00000240], rax
    "48 8D 7C 24 ??"        // lea rdi, [rsp+40]
    "C6 44 24 ?? 00"        // mov byte ptr [rsp+38], 00
    "48 89 7C 24 ??"        // mov [rsp+20], rdi
    "48 89 7C 24 ??"        // mov [rsp+28], rdi
    "48 8D 84 24 ????????"  // lea rax, [rsp+00000240]
    "48 89 44 24 30"        // mov [rsp+30], rax
    "48 85 D2"              // test rdx, rdx
    "74 52"                 // je Borderlands4.exe+116ABD6
    "48 89 D6"              // mov rsi, rdx
    "48 89 D1"              // mov rcx, rdx
    "FF 15 ????????"        // call qword ptr [Borderlands4.exe+10CCAFA0] { ->ucrtbase.wcslen }
    "49 89 C6"              // mov r14, rax
    "49 63 DE"              // movsxd rbx, r14d
    "81 FB 00010000"        // cmp ebx, 00000100
    "7D 07"                 // jnl Borderlands4.exe+116ABA5
    "45 85 F6"              // test r14d, r14d
    "75 14"                 // jne Borderlands4.exe+116ABB7
    "EB 31"                 // jmp Borderlands4.exe+116ABD6
    "48 8D 4C 24 ??"        // lea rcx, [rsp+20]
    "48 89 DA"              // mov rdx, rbx
    "E8 ????????"           // call Borderlands4.exe+10F8100
    "48 8B 7C 24 ??"        // mov rdi, [rsp+28]
    "49 C1 E6 20"           // shl r14, 20
    "49 C1 FE 1F"           // sar r14, 1F
    "48 89 F9"              // mov rcx, rdi
    "48 89 F2"              // mov rdx, rsi
    "4D 89 F0"              // mov r8, r14
    "E8 ????????"           // call Borderlands4.exe+E74B790 { ->->VCRUNTIME140.memcpy }
    "48 8D 04 5F"           // lea rax, [rdi+rbx*2]
    "48 89 44 24 ??"        // mov [rsp+28], rax
    "48 8D 4C 24 ??"        // lea rcx, [rsp+20]
    "B2 01"                 // mov dl, 01
    "E8 ????????"           // call Borderlands4.exe+1169EA0
    "48 8B 44 24 ??"        // mov rax, [rsp+28]
    "66 C7 00 0000"         // mov word ptr [rax], 0000
    "48 8B 4C 24 ??"        // mov rcx, [rsp+20]
    "FF 15 ????????"  // call qword ptr [Borderlands4.exe+10CC9250] { ->->KERNELBASE.DeleteFileW }
    "80 7C 24 ?? 01"  // cmp byte ptr [rsp+38], 01
    "75 53"           // jne Borderlands4.exe+116AC51
    "48 8B 54 24 ??"  // mov rdx, [rsp+20]
    "48 85 D2"        // test rdx, rdx
    "74 49"           // je Borderlands4.exe+116AC51
    "48 8B 0D ????????"        // mov rcx, [Borderlands4.exe+114F8EA0]
    "48 85 C9"                 // test rcx, rcx
    "74 0B"                    // je Borderlands4.exe+116AC1F
    "4C 8B 01"                 // mov r8, [rcx]
    "89 C6"                    // mov esi, eax
    "41 FF 50 48"              // call qword ptr [r8+48]
    "EB 30"                    // jmp Borderlands4.exe+116AC4F
    "89 C6"                    // mov esi, eax
    "8B 05 ????????"           // mov eax, [Borderlands4.exe+114D2468]
    "8B 0D ????????"           // mov ecx, [Borderlands4.AK::IAkStreamMgr::m_pStreamMgr+15AC]
    "65 4C 8B 04 25 ????????"  // mov r8, gs:[00000058]
    "49 8B 0C C8"              // mov rcx, [r8+rcx*8]
    "3B 81 ????????"           // cmp eax, [rcx+00000110]
    "7F 3B"                    // jg Borderlands4.exe+116AC7D
    "48 8B 0D ????????"        // mov rcx, [Borderlands4.exe+114F8EA0]
    "48 8B 01"                 // mov rax, [rcx]
    "FF 50 48"                 // call qword ptr [rax+48]
    "89 F0"                    // mov eax, esi
    "85 C0"                    // test eax, eax
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
                    log::error("error in delete character hook: {}", ex.what());
                } catch (...) {
                    log::error("unknown error in delete character hook");
                }

                return ret;
            }
        }

    } catch (const std::exception& ex) {
        log::error("error in delete character hook: {}", ex.what());
    } catch (...) {
        log::error("unknown error in delete character hook");
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

    detour(SAVE_FILE_SIG, save_file_hook, &save_file_ptr, "save file");
    detour(DELETE_CHARACTER_SIG, delete_character_hook, &delete_character_ptr, "delete character");
}

}  // namespace b4ac
