# WARNING: keystone is licensed under GPLv2
CPMAddPackage(
    NAME keystone
    VERSION 0.9.2
    GIT_REPOSITORY https://github.com/keystone-engine/keystone
    GIT_TAG 18569351000cf1b8bd1ea2cc8a02c2e17b76391f
    OPTIONS
        "BUILD_LIBS_ONLY ON"
)
target_include_directories(keystone PUBLIC ${keystone_SOURCE_DIR}/include)