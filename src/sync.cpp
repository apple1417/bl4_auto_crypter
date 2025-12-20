#include "pch.h"
#include "sync.h"
#include "crypter.h"
#include "logging.h"

namespace b4ac {

namespace {

// In the plugin, we trigger all syncing from our own thread, since encryption/decryption can be
// quite slow, and to help deal with the fact that the hooks are each triggered on their own thread,
// which could cause us to trigger syncing twice at the same time
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
                log::debug("syncing...");
                internal::sync_all_saves();
            } catch (const std::exception& ex) {
                log::error("error while syncing saves: {}", ex.what());
            } catch (...) {
                log::error("unknown error while syncing saves");
            }

            // While we're syncing, another thread might save a new file and clear the flag
        }
    }
}

}  // namespace

void start_syncing_thread(void) {
    // Since the flag is clear by default, first run will do an inital sync
    std::thread(syncing_thread).detach();
}

void trigger_sync(void) {
    syncing_finished.clear();
    syncing_finished.notify_all();
}

namespace {

std::unordered_map<std::filesystem::path, std::filesystem::file_time_type> previous_write_times{};

/**
 * @brief Creates a backup of a file that caused an encryption/decryption error.
 *
 * @param file The file to back up.
 */
void backup_failing_file(const std::filesystem::path& file) {
    try {
        auto error_folder = file.parent_path() / "bl4_auto_crypter errors";
        std::filesystem::create_directories(error_folder);

        // don't need to care about duplicates if we name everything using it's hash
        auto backup_path = (error_folder / sha1_file(file)).replace_extension(file.extension());
        // Any .sav file, even in a subfolder, is added to steam cloud, so add our own extension to
        // avoid that
        backup_path += ".b4ac";

        std::filesystem::copy_file(file, backup_path, std::filesystem::copy_options::skip_existing);

    } catch (const std::exception& ex) {
        log::error("error backing up failing file: {}", ex.what());
    } catch (...) {
        log::error("unknown error backing up failing file");
    }
}

/**
 * @brief Gets the file's last write time.
 *
 * @param path The file to check.
 * @return The file's last write time, or the oldest possible time if it doesn't exist.
 */
std::filesystem::file_time_type get_write_time_or_min(const std::filesystem::path& path) {
    return std::filesystem::exists(path) ? std::filesystem::last_write_time(path)
                                         : std::filesystem::file_time_type::min();
}

/**
 * @brief Gets the timestamp we last saw the given file at.
 *
 * @param path The file to check.
 * @return The last time it was modified, or the newest possible time if we haven't seen it before.
 */
std::filesystem::file_time_type get_previous_write_time_or_max(const std::filesystem::path& path) {
    auto ittr = previous_write_times.find(path);
    if (ittr == previous_write_times.end()) {
        return std::filesystem::file_time_type::max();
    }
    return (*ittr).second;
}

/**
 * @brief Syncs a single sav-yaml pair.
 *
 * @param folder The folder the file is in.
 * @param key The crypto key for this folder.
 * @param stem The stem of the file pair to sync.
 */
void sync_single_pair(const std::filesystem::path& folder,
                      const crypto_key& key,
                      const std::filesystem::path& stem) {
    auto sav = std::filesystem::path{folder / stem}.replace_extension(".sav");
    auto yaml = std::filesystem::path{folder / stem}.replace_extension(".yaml");

    // Files that don't exist yet get the oldest possible time, so any other time on the other file
    // is newer than it
    auto sav_time = get_write_time_or_min(sav);
    auto yaml_time = get_write_time_or_min(yaml);

    // Neither file's changed since we last saw it, can early exit
    // Since this returns the newest possible time, it can't be equal to the oldest possible time
    // from above
    if (sav_time == get_previous_write_time_or_max(sav)
        && yaml_time == get_previous_write_time_or_max(yaml)) {
        return;
    }

    log::debug("sav time: {}, yaml time: {}", sav_time, yaml_time);

    auto update_previous_times = [&sav, &yaml](void) {
        previous_write_times[sav] = get_write_time_or_min(sav);
        previous_write_times[yaml] = get_write_time_or_min(yaml);
    };

    // Write a temporary file at first, in case something modifies our target while we're working
    std::filesystem::path tmp;
    const std::filesystem::path* target{};  // rather not copy

    // Prefer the sav when equal
    if (sav_time >= yaml_time) {
        target = &yaml;
        tmp = std::filesystem::path{yaml}.replace_extension(".yaml.b4ac");

        try {
            decrypt(tmp, sav, key);
        } catch (const std::exception& ex) {
            log::error("error decrypting file {}: {}", sav.string(), ex.what());
            backup_failing_file(sav);
            update_previous_times();
            return;
        } catch (...) {
            log::error("unknown error decrypting file {}", sav.string());
            backup_failing_file(sav);
            update_previous_times();
            return;
        }
    } else {
        target = &sav;
        tmp = std::filesystem::path{sav}.replace_extension(".sav.b4ac");

        try {
            encrypt(tmp, yaml, key);
        } catch (const std::exception& ex) {
            log::error("error encrypting file {}: {}", yaml.string(), ex.what());
            backup_failing_file(yaml);
            update_previous_times();
            return;
        } catch (...) {
            log::error("unknown error encrypting file {}", yaml.string());
            backup_failing_file(yaml);
            update_previous_times();
            return;
        }
    }

    auto new_sav_time = get_write_time_or_min(sav);
    auto new_yaml_time = get_write_time_or_min(yaml);

    if (sav_time != new_sav_time || yaml_time != new_yaml_time) {
        // Something modified one of the files while we were working on it. Give up and retry.
        log::debug("file modified, discarding");
        std::filesystem::remove(tmp);
        trigger_sync();
        return;
    }
    // Technically we still have a slight race condition here - the crypto/compression takes by far
    // the longest, but it's still possible for something to get modified between us grabbing the
    // time and replacing the file
    // If we get two events on the same file so close to each other, deciding we don't care

    // This is defined as overwriting existing files, which is what we want
    std::filesystem::rename(tmp, *target);

    update_previous_times();
    log::debug("new times sav: {}, yaml: {}", previous_write_times[sav],
               previous_write_times[yaml]);
}

}  // namespace

namespace internal {

void sync_saves_in_folder(const std::filesystem::path& folder, const crypto_key& key) {
    auto valid_stems = std::ranges::to<std::unordered_set>(
        std::views::all(std::filesystem::directory_iterator{folder})
        | std::views::filter([](const auto& entry) {
              if (!entry.is_regular_file() && !entry.is_symlink()) {
                  return false;
              }

              auto extension = entry.path().extension();
              return extension == ".sav" || extension == ".yaml";
          })
        | std::views::transform([](auto& entry) { return entry.path().stem(); }));

    for (auto& stem : valid_stems) {
        sync_single_pair(folder, key, stem);
    }
}

}  // namespace internal

namespace {

std::filesystem::path get_saves_folder(void) {
    std::optional<std::filesystem::path> saves_folder = std::nullopt;
    if (saves_folder) {
        return *saves_folder;
    }

    PWSTR raw_path = nullptr;
    auto ret = SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &raw_path);
    // Need to free regardless of if the call actually succeeded, so make a copy first
    const std::filesystem::path std_path = raw_path == nullptr ? L"" : raw_path;
    CoTaskMemFree(raw_path);

    if (ret != S_OK) {
        throw std::runtime_error("couldn't get my documents path");
    }

    saves_folder = std_path / "My Games" / "Borderlands 4" / "Saved" / "SaveGames";
    return *saves_folder;
}

std::unordered_map<std::filesystem::path, std::pair<std::filesystem::path, crypto_key>>
    known_keys{};
std::unordered_set<std::filesystem::path> known_bad_paths{};

}  // namespace

namespace internal {

void sync_all_saves(void) {
    for (const auto& entry : std::filesystem::directory_iterator{get_saves_folder()}) {
        if (!entry.is_directory()) {
            continue;
        }

        if (known_bad_paths.contains(entry.path())) {
            continue;
        }
        if (known_keys.contains(entry.path())) {
            auto [folder, key] = known_keys[entry.path()];
            sync_saves_in_folder(folder, key);
            continue;
        }

        crypto_key key{};
        if (!parse_key(entry.path().filename().string(), key)) {
            log::error("Couldn't extract crypto key from folder: {}", entry.path().string());
            known_bad_paths.insert(entry.path());
            continue;
        }

        auto saves_dir = entry.path() / "Profiles" / "client";
        known_keys[entry.path()] = {saves_dir, key};
        sync_saves_in_folder(saves_dir, key);
    }
}

}  // namespace internal

}  // namespace b4ac
