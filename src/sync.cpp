#include "pch.h"
#include "sync.h"
#include "crypter.h"

namespace b4ac {

namespace {

std::unordered_map<std::filesystem::path, std::filesystem::file_time_type> cached_write_times{};

}

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
        auto sav = std::filesystem::path{folder / stem}.replace_extension(".sav");
        auto yaml = std::filesystem::path{folder / stem}.replace_extension(".yaml");

        // Files that don't exist yet the newest possible time
        auto sav_time = std::filesystem::exists(sav)
                            ? std::filesystem::last_write_time(sav)
                            : std::numeric_limits<std::filesystem::file_time_type>::max();
        auto yaml_time = std::filesystem::exists(yaml)
                             ? std::filesystem::last_write_time(yaml)
                             : std::numeric_limits<std::filesystem::file_time_type>::max();

        auto get_cached = [](auto& path) -> std::filesystem::file_time_type {
            auto ittr = cached_write_times.find(path);
            if (ittr == cached_write_times.end()) {
                //  Cache values that don't exist get the oldest possible time
                return std::numeric_limits<std::filesystem::file_time_type>::min();
            }
            return (*ittr).second;
        };

        // No need to process if it hasn't changed since we saw it last
        if (sav_time == get_cached(sav) && yaml_time == get_cached(yaml)) {
            continue;
        }

        // Prefer the sav when equal
        if (sav_time >= yaml_time) {
            decrypt(yaml, sav, key);
            sav_time = std::filesystem::last_write_time(sav);
        } else {
            encrypt(sav, yaml, key);
            yaml_time = std::filesystem::last_write_time(yaml);
        }

        // It's possible both times have updated since we saw them last - e.g. on the first call
        cached_write_times[sav] = sav_time;
        cached_write_times[yaml] = yaml_time;
    }
}

}  // namespace b4ac
