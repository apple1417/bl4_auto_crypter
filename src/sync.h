#include "pch.h"
#include "crypter.h"

namespace b4ac {

/**
 * @brief Makes sure every save file in the given folder has a synced .sav and .yaml version.
 *
 * @param folder The folder to syncronize.
 * @param key The crypto key for this folder.
 */
void sync_saves(const std::filesystem::path& folder, const crypto_key& key);

}  // namespace b4ac
