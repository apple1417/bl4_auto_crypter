#include "pch.h"
#include "sync.h"
#include "crypter.h"

namespace b4ac {

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
        std::filesystem::copy_file(file, backup_path, std::filesystem::copy_options::skip_existing);

    } catch (const std::exception& ex) {
        std::cerr << "[b4ac] error backing up failing file: " << ex.what() << "\n" << std::flush;
    } catch (...) {
        std::cerr << "[b4ac] unknown error backing up failing file\n" << std::flush;
    }
}

/**
 * @brief Gets the timestamp we last saw the given file at.
 *
 * @param path The file to check.
 * @return The last time it was modified, or the newest possible time if we haven't seen it before.
 */
std::filesystem::file_time_type get_previous_time(const std::filesystem::path& path) {
    auto ittr = previous_write_times.find(path);
    if (ittr == previous_write_times.end()) {
        return std::numeric_limits<std::filesystem::file_time_type>::max();
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
    auto sav_time = std::filesystem::exists(sav)
                        ? std::filesystem::last_write_time(sav)
                        : std::numeric_limits<std::filesystem::file_time_type>::min();
    auto yaml_time = std::filesystem::exists(yaml)
                         ? std::filesystem::last_write_time(yaml)
                         : std::numeric_limits<std::filesystem::file_time_type>::min();

    // Neither file's changed since we last saw it, can early exit
    // Since this returns the newest possible time, it can't be equal to the oldest possible time
    // from above
    if (sav_time == get_previous_time(sav) && yaml_time == get_previous_time(yaml)) {
        return;
    }

    // Prefer the sav when equal
    if (sav_time >= yaml_time) {
        try {
            decrypt(yaml, sav, key);
        } catch (const std::exception& ex) {
            std::cerr << "[b4ac] error decrypting file " << yaml.string() << ": " << ex.what()
                      << "\n"
                      << std::flush;
            backup_failing_file(sav);
        } catch (...) {
            std::cerr << "[b4ac] unknown error decrypting file " << yaml.string() << "\n"
                      << std::flush;
            backup_failing_file(sav);
        }

        sav_time = std::filesystem::last_write_time(sav);
    } else {
        try {
            encrypt(sav, yaml, key);
        } catch (const std::exception& ex) {
            std::cerr << "[b4ac] error encrypting file " << yaml.string() << ": " << ex.what()
                      << "\n"
                      << std::flush;
            backup_failing_file(yaml);
        } catch (...) {
            std::cerr << "[b4ac] unknown error encrypting file " << yaml.string() << "\n"
                      << std::flush;
            backup_failing_file(yaml);
        }
        yaml_time = std::filesystem::last_write_time(yaml);
    }

    // It's possible both times have updated since we saw them last - e.g. on the first call
    previous_write_times[sav] = sav_time;
    previous_write_times[yaml] = yaml_time;
}

}  // namespace

void sync_saves(const std::filesystem::path& folder, const crypto_key& key) {
    auto valid_stems = std::ranges::to<std::unordered_set>(
        std::views::all(std::filesystem::directory_iterator{folder})
        | std::views::filter([](auto& entry) {
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

}  // namespace b4ac
