#ifndef SYNC_H
#define SYNC_H

#include "pch.h"
#include "crypter.h"

namespace b4ac {

/**
 * @brief Starts the syncing thread, and triggers an initial sync.
 */
void start_syncing_thread(void);

/**
 * @brief Trigger a new save sync.
 */
void trigger_sync(void);

namespace internal {
// Mostly just exposed for the tests

/**
 * @brief Makes sure every save file in the given folder has a synced .sav and .yaml version.
 *
 * @param folder The folder to synchronize.
 * @param key The crypto key for this folder.
 */
void sync_saves_in_folder(const std::filesystem::path& folder, const crypto_key& key);

/**
 * @brief Makes sure every save file we can find has a synced .sav and .yaml version.
 * @note Checks all folders in Documents/My Games/...
 */
void sync_all_saves(void);

}  // namespace internal

}  // namespace b4ac

#endif /* SYNC_H */
