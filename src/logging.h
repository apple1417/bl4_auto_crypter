#ifndef LOGGING_H
#define LOGGING_H

#include "pch.h"

namespace b4ac::log {

#ifdef B4AC_LOG_TO_FILE
extern std::ofstream log_file_stream;
#endif

/**
 * @brief Logs an error message.
 *
 * @tparam Args Format args types (automatic).
 * @param fmt Format string.
 * @param args Format args.
 */
template <typename... Args>
void error(std::format_string<Args...> fmt, Args&&... args) {
    auto msg = std::format("[b4ac] {}\n", std::format(fmt, std::forward<Args>(args)...));
    // Rough thought: a single finished string is less likely to get broken by multithreading
    std::cerr << msg << std::flush;
#ifdef B4AC_LOG_TO_FILE
    log_file_stream << "E " << msg << std::flush;
#endif
}

/**
 * @brief Logs an info message.
 *
 * @tparam Args Format args types (automatic).
 * @param fmt Format string.
 * @param args Format args.
 */
template <typename... Args>
void info(std::format_string<Args...> fmt, Args&&... args) {
    auto msg = std::format("[b4ac] {}\n", std::format(fmt, std::forward<Args>(args)...));
    std::cout << msg << std::flush;
#ifdef B4AC_LOG_TO_FILE
    log_file_stream << "I " << msg << std::flush;
#endif
}

/**
 * @brief Logs a debug message.
 *
 * @tparam Args Format args types (automatic).
 * @param fmt Format string.
 * @param args Format args.
 */
template <typename... Args>
void debug([[maybe_unused]] std::format_string<Args...> fmt, [[maybe_unused]] Args&&... args) {
#ifdef B4AC_DEBUG_LOGGING
    auto msg = std::format("[b4ac] {}\n", std::format(fmt, std::forward<Args>(args)...));
    std::cout << msg << std::flush;
#ifdef B4AC_LOG_TO_FILE
    log_file_stream << "D " << msg << std::flush;
#endif
#endif
}

}  // namespace b4ac::log

#endif /* LOGGING_H */
