#include "pch.h"
#include "crypter.h"
#include "sync.h"

#ifdef CRYPTER_EXE

namespace {

int sync_impl(int argc, char* argv[], bool wait) {
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (argc != 4) {
        std::cerr << "wrong num args\n";
        return 1;
    }

    b4ac::crypto_key key;
    if (!b4ac::parse_key(argv[2], key)) {
        std::cerr << "couldn't parse key: " << argv[2] << "\n";
        return 1;
    }

    std::filesystem::path folder{argv[3]};
    if (!std::filesystem::exists(folder)) {
        std::cerr << "couldn't find folder: " << argv[3] << "\n";
        return 1;
    }

    b4ac::sync_saves(folder, key);

    if (wait) {
        std::cout << "first sync done; waiting for input\n" << std::flush;

        char dummy{};
        std::cin >> dummy;

        b4ac::sync_saves(folder, key);
    }

    return 0;
}

int crypt_impl(int argc, char* argv[], bool encrypt) {
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (argc != 5) {
        std::cerr << "wrong num args\n";
        return 1;
    }

    b4ac::crypto_key key;
    if (!b4ac::parse_key(argv[2], key)) {
        std::cerr << "couldn't parse key: " << argv[2] << "\n";
        return 1;
    }

    std::filesystem::path input{argv[3]};
    if (!std::filesystem::exists(input)) {
        std::cerr << "couldn't find input: " << argv[3] << "\n";
        return 1;
    }

    std::filesystem::path output{argv[4]};
    // nothing to check?

    if (encrypt) {
        b4ac::encrypt(output, input, key);
    } else {
        b4ac::decrypt(output, input, key);
    }

    return 0;
}

int hash_impl(int argc, char* argv[]) {
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (argc != 3) {
        std::cerr << "wrong num args\n";
        return 1;
    }

    std::filesystem::path input{argv[2]};
    if (!std::filesystem::exists(input)) {
        std::cerr << "couldn't find input: " << argv[2] << "\n";
        return 1;
    }

    std::cout << b4ac::sha1_file(input) << "\n";
    return 0;
}

int main_impl(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "wrong num args\n";
        return 1;
    }

    auto action = *argv[1];
    if (action == 'd') {
        return crypt_impl(argc, argv, false);
    }
    if (action == 'e') {
        return crypt_impl(argc, argv, true);
    }
    if (action == 's') {
        return sync_impl(argc, argv, false);
    }
    if (action == 'S') {
        return sync_impl(argc, argv, true);
    }
    if (action == 'h') {
        return hash_impl(argc, argv);
    }

    std::cerr << "bad action: " << action << "\n";
    return 1;
}

}  // namespace

// NOLINTNEXTLINE(misc-use-internal-linkage)
int main(int argc, char* argv[]) {
    auto ret = main_impl(argc, argv);
    if (ret != 0) {
        // clang-format off
        std::cerr << "usage: " << argv[0] << " <d|e> <key> <input> <output>\n"
                     "       " << argv[0] << " <s|S> <key> <folder>\n"
                     "       " << argv[0] << " <h> <file>\n";
        // clang-format on
    }
    return ret;
}

#endif
