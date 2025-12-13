#include "pch.h"
#include "hooks.h"
#include "memory.h"
#include "sync.h"

namespace b4ac {

namespace {

/**
 * @brief Helper class to detect a reentrant call.
 *
 * Sample usage:
 *     static ReentrancyGuard guard{};
 *     auto rentrant = guard.claim();
 *     if (rentrant) { ... }
 *
 * guard.claim() returns a RAII class - you must store it in a variable to prevent it immediately
 * destruting and considering the call over.
 */
struct ReentrancyGuard {
   private:
    std::atomic<int> counter = 0;

    struct Claimer {
       private:
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
        std::atomic<int>& counter;
        bool reentrant;

       public:
        Claimer(std::atomic<int>& counter) : counter(counter), reentrant(this->counter++ != 0) {}
        ~Claimer() { this->counter--; }

        operator bool(void) const { return this->reentrant; }

        Claimer(const Claimer&) = delete;
        Claimer(Claimer&&) = delete;
        Claimer& operator=(const Claimer&) = delete;
        Claimer& operator=(Claimer&&) = delete;
    };

   public:
    Claimer claim(void) { return {this->counter}; }
};

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

using save_file_func = uint64_t(void* param_1, void* param_2, void* param_3);
save_file_func* save_file_ptr;

const constinit Pattern<41> SAVE_FILE_SIG{
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
    "48 89 D7"             // mov rdi, rdx
};

uint64_t save_file_hook(void* param_1, void* param_2, void* param_3) {
    try {
#ifdef B4AC_DEBUG_LOGGING
        const Logger log{"save file"};
#endif
        // Somehow this function appears to be re-entrant?
        // Since we want to sync after it's finished saving, only run after the top level call
        static ReentrancyGuard guard{};
        auto rentrant = guard.claim();
        if (rentrant) {
            return save_file_ptr(param_1, param_2, param_3);
        }

        auto ret = save_file_ptr(param_1, param_2, param_3);
        // Have to start a new try-catch after calling the original function, since we don't want
        // an exception to re-call it a second time at the bottom of the function
        try {
            sync_all_saves();
        } catch (const std::exception& ex) {
            std::cerr << "[b4ac] error in save file hook: " << ex.what() << "\n" << std::flush;
        } catch (...) {
            std::cerr << "[b4ac] unknown error in save file hook\n" << std::flush;
        }

        return ret;
    } catch (const std::exception& ex) {
        std::cerr << "[b4ac] error in save file hook: " << ex.what() << "\n" << std::flush;
    } catch (...) {
        std::cerr << "[b4ac] unknown error in save file hook\n" << std::flush;
    }

    return save_file_ptr(param_1, param_2, param_3);
}
static_assert(std::is_same_v<decltype(save_file_hook), save_file_func>);

}  // namespace
#pragma endregion

#pragma region delete character
namespace {

using delete_character_func = bool(void* param_1, wchar_t* save_file);
delete_character_func* delete_character_ptr;

// Yes this is the best sig it gave me :/
// When it inevitably breaks, way to find it is just breakpoint on DeleteFileW, delete a character,
// then go one up the stack
const constinit Pattern<275> DELETE_CHARACTER_SIG{
    "41 56"                 // push r14
    "56"                    // push rsi
    "57"                    // push rdi
    "53"                    // push rbx
    "48 81 EC ????????"     // sub rsp, 00000248
    "48 8B 05 ????????"     // mov rax, [Borderlands4.exe+1123D940]
    "48 31 E0"              // xor rax, rsp
    "48 89 84 24 ????????"  // mov [rsp+00000240], rax
    "48 8D 7C 24 ??"        // lea rdi, [rsp+40]
    "C6 44 24 ?? 00"        // mov byte ptr [rsp+38], 00
    "48 89 7C 24 ??"        // mov [rsp+20], rdi
    "48 89 7C 24 ??"        // mov [rsp+28], rdi
    "48 8D 84 24 ????????"  // lea rax, [rsp+00000240]
    "48 89 44 24 ??"        // mov [rsp+30], rax
    "48 85 D2"              // test rdx, rdx
    "74 ??"                 // je Borderlands4.exe+1169726
    "48 89 D6"              // mov rsi, rdx
    "48 89 D1"              // mov rcx, rdx
    "FF 15 ????????"        // call qword ptr [Borderlands4.exe+10B758D8] { ->ucrtbase.wcslen }
    "49 89 C6"              // mov r14, rax
    "49 63 DE"              // movsxd rbx, r14d
    "81 FB ????????"        // cmp ebx, 00000100
    "7D ??"                 // jnl Borderlands4.exe+11696F5
    "45 85 F6"              // test r14d, r14d
    "75 ??"                 // jne Borderlands4.exe+1169707
    "EB ??"                 // jmp Borderlands4.exe+1169726
    "48 8D 4C 24 ??"        // lea rcx, [rsp+20]
    "48 89 DA"              // mov rdx, rbx
    "E8 ????????"           // call Borderlands4.exe+10F6F60
    "48 8B 7C 24 ??"        // mov rdi, [rsp+28]
    "49 C1 E6 20"           // shl r14, 20
    "49 C1 FE 1F"           // sar r14, 1F
    "48 89 F9"              // mov rcx, rdi
    "48 89 F2"              // mov rdx, rsi
    "4D 89 F0"              // mov r8, r14
    "E8 ????????"           // call Borderlands4.exe+E6198F0 { ->->VCRUNTIME140.memcpy }
    "48 8D 04 ??"           // lea rax, [rdi+rbx*2]
    "48 89 44 24 ??"        // mov [rsp+28], rax
    "48 8D 4C 24 ??"        // lea rcx, [rsp+20]
    "B2 01"                 // mov dl, 01
    "E8 ????????"           // call Borderlands4.exe+11689F0
    "48 8B 44 24 ??"        // mov rax, [rsp+28]
    "66 C7 00 0000"         // mov word ptr [rax], 0000
    "48 8B 4C 24 ??"        // mov rcx, [rsp+20]
    "FF 15 ????????"  // call qword ptr [Borderlands4.exe+10B73B88] { ->->KERNELBASE.DeleteFileW }
    "80 7C 24 ?? 01"  // cmp byte ptr [rsp+38], 01
    "75 ??"           // jne Borderlands4.exe+11697A1
    "48 8B 54 24 ??"  // mov rdx, [rsp+20]
    "48 85 D2"        // test rdx, rdx
    "74 ??"           // je Borderlands4.exe+11697A1
    "48 8B 0D ????????"        // mov rcx, [Borderlands4.exe+1139CDA0]
    "48 85 C9"                 // test rcx, rcx
    "74 ??"                    // je Borderlands4.exe+116976F
    "4C 8B 01"                 // mov r8, [rcx]
    "89 C6"                    // mov esi, eax
    "41 FF 50 ??"              // call qword ptr [r8+48]
    "EB ??"                    // jmp Borderlands4.exe+116979F
    "89 C6"                    // mov esi, eax
    "8B 05 ????????"           // mov eax, [Borderlands4.exe+11376368]
    "8B 0D ????????"           // mov ecx, [Borderlands4.AK::IAkStreamMgr::m_pStreamMgr+15AC]
    "65 4C 8B 04 25 ????????"  // mov r8, gs:[00000058]
    "49 8B 0C ??"              // mov rcx, [r8+rcx*8]
    "3B 81 ????????"           // cmp eax, [rcx+00000110]
    "7F ??"                    // jg Borderlands4.exe+11697CD
    "48 8B 0D ????????"        // mov rcx, [Borderlands4.exe+1139CDA0]
    "48 8B 01"                 // mov rax, [rcx]
    "FF 50 ??"                 // call qword ptr [rax+48]
    "89 F0"                    // mov eax, esi
    "85 C0"                    // test eax, eax
};

bool delete_character_hook(void* param_1, wchar_t* save_file) {
    try {
#ifdef B4AC_DEBUG_LOGGING
        const Logger log{"delete character"};
#endif

        const std::filesystem::path sav = save_file;
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

    detour(SAVE_FILE_SIG, save_file_hook, &save_file_ptr, "save file");
    detour(DELETE_CHARACTER_SIG, delete_character_hook, &delete_character_ptr, "delete character");
}

}  // namespace b4ac
