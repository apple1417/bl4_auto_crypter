cmake_minimum_required(VERSION 3.28)
project(bl4_auto_crypter VERSION 1)

file(GLOB_RECURSE sources CONFIGURE_DEPENDS "src/*.cpp" "src/*.h")
list(APPEND sources "src/versioninfo.rc")

add_executable(crypter_exe ${sources})
add_library(crypter_plugin SHARED ${sources})

set(CONFIGURE_FILES_DIR "${CMAKE_CURRENT_BINARY_DIR}/configure")

configure_file("src/version.inl.in" "${CONFIGURE_FILES_DIR}/version.inl")

set(GIT_PRE_CONFIGURE_FILE "src/git.inl.in")
set(GIT_POST_CONFIGURE_FILE "${CONFIGURE_FILES_DIR}/git.inl")
include(common_cmake/git_watcher.cmake)

function(add_common_args target_name)
    target_compile_features(${target_name} PUBLIC cxx_std_23)
    set_target_properties(${target_name} PROPERTIES
        COMPILE_WARNING_AS_ERROR True
        INTERPROCEDURAL_OPTIMIZATION True
        EXPORT_COMPILE_COMMANDS True
        PREFIX ""
    )

    if(MSVC)
        # Under MSVC, enable edit and continue in debug - which conflicts with LTO
        set_target_properties(${target_name} PROPERTIES
            MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug>:EditAndContinue>"
            INTERPROCEDURAL_OPTIMIZATION $<CONFIG:Release>
        )
    elseif(MINGW)
        # Under MinGW, only enable LTO in release mode - it causes linking errors in debug
        set_target_properties(${target_name} PROPERTIES
            INTERPROCEDURAL_OPTIMIZATION $<CONFIG:Release>
        )
    endif()

    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4)
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    # CMake doesn't understand warnings as errors for MinGW yet
    if(MINGW)
        target_compile_options(${target_name} PRIVATE -Werror)
    endif()

    target_precompile_headers(${target_name} PUBLIC "src/pch.h")
    target_include_directories(${target_name} PUBLIC "src" "${CONFIGURE_FILES_DIR}")
    target_link_libraries(${target_name} PUBLIC Bcrypt.dll)
endfunction()

add_common_args(crypter_exe)
add_common_args(crypter_plugin)

target_compile_definitions(crypter_exe PUBLIC CRYPTER_EXE)
target_compile_definitions(crypter_plugin PUBLIC CRYPTER_PLUGIN)

install(
    TARGETS
       crypter_exe
       crypter_plugin
    RUNTIME DESTINATION
        .
)
