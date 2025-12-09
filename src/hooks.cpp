#include "pch.h"
#include "hooks.h"
#include "memory.h"
#include "sync.h"

namespace b4ac {

#pragma region list saves
namespace {

using list_saves_func =
    void*(void* param_1, void* param_2, void* param_3, void* param_4, char param_5);
list_saves_func* list_saves_ptr;

const constinit Pattern<26> LIST_SAVES_SIG{
    "41 57 41 56 41 54 56 57 55 53 48 83 EC 50 4C 89 CB 4C 89 C7 48 89 D6 49 89 CE"};

void* list_saves_hook(void* param_1, void* param_2, void* param_3, void* param_4, char param_5) {
    try {
        sync_all_saves();
    } catch (const std::exception& ex) {
        std::cerr << "[b4ac] error in list saves hook: " << ex.what() << "\n" << std::flush;
    } catch (...) {
        std::cerr << "[b4ac] unknown error in list saves hook\n" << std::flush;
    }

    return list_saves_ptr(param_1, param_2, param_3, param_4, param_5);
}
static_assert(std::is_same_v<decltype(list_saves_hook), list_saves_func>);

}  // namespace
#pragma endregion

#pragma region save file
namespace {

using save_file_func = uint64_t(void* param_1, void* param_2, void* param_3);
save_file_func* save_file_ptr;

const constinit Pattern<38> SAVE_FILE_SIG{
    "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC E8 00 00 00 0F 29 BC 24 ?? ?? ?? ?? 0F 29 B4 24 "
    "?? ?? ?? ?? 4D 89 C6"};

uint64_t save_file_hook(void* param_1, void* param_2, void* param_3) {
    auto ret = save_file_ptr(param_1, param_2, param_3);

    try {
        sync_all_saves();
    } catch (const std::exception& ex) {
        std::cerr << "[b4ac] error in save file hook: " << ex.what() << "\n" << std::flush;
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

// yes this is the best sig it gave me :/
const constinit Pattern<275> DELETE_CHARACTER_SIG{
    "41 56 56 57 53 48 81 EC 48 02 00 00 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 84 24 ?? ?? ?? ?? 48 "
    "8D 7C 24 ?? C6 44 24 ?? 00 48 89 7C 24 ?? 48 89 7C 24 ?? 48 8D 84 24 ?? ?? ?? ?? 48 89 44 24 "
    "?? 48 85 D2 74 ?? 48 89 D6 48 89 D1 FF 15 ?? ?? ?? ?? 49 89 C6 49 63 DE 81 FB 00 01 00 00 7D "
    "?? 45 85 F6 75 ?? EB ?? 48 8D 4C 24 ?? 48 89 DA E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 49 C1 E6 20 49 "
    "C1 FE 1F 48 89 F9 48 89 F2 4D 89 F0 E8 ?? ?? ?? ?? 48 8D 04 ?? 48 89 44 24 ?? 48 8D 4C 24 ?? "
    "B2 01 E8 ?? ?? ?? ?? 48 8B 44 24 ?? 66 C7 00 00 00 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 80 7C 24 "
    "?? 01 75 ?? 48 8B 54 24 ?? 48 85 D2 74 ?? 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 4C 8B 01 89 C6 "
    "41 FF 50 ?? EB ?? 89 C6 8B 05 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 65 4C 8B 04 25 ?? ?? ?? ?? 49 8B "
    "0C ?? 3B 81 ?? ?? ?? ?? 7F ?? 48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 ?? 89 F0 85 C0"};

bool delete_character_hook(void* param_1, wchar_t* save_file) {
    try {
        std::filesystem::path sav = save_file;
        auto yaml = std::filesystem::path{sav}.replace_extension(".yaml");

        // If we're trying to delete a save which has an equivalent yaml
        if (std::filesystem::exists(sav) && std::filesystem::exists(yaml)) {
            auto ret = delete_character_ptr(param_1, save_file);

            try {
                // If it truely did remove the save, remove the yaml too
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
    detour(LIST_SAVES_SIG, list_saves_hook, &list_saves_ptr, "list saves");
    detour(SAVE_FILE_SIG, save_file_hook, &save_file_ptr, "save file");
    detour(DELETE_CHARACTER_SIG, delete_character_hook, &delete_character_ptr, "delete character");
}

}  // namespace b4ac
