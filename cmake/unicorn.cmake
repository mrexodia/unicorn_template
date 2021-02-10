# WARNING: unicorn is licensed under GPLv2
CPMAddPackage(
    NAME unicorn
    GIT_REPOSITORY https://github.com/mrexodia/unicorn
    GIT_TAG 42d0682c6c04bf8e5bf9e5d7d0075b82b218af55
    OPTIONS
        "BUILD_SHARED_LIBS OFF"
        "UNICORN_BUILD_SAMPLES OFF"
        "UNICORN_INSTALL OFF"
        "UNICORN_STATIC_MSVCRT OFF"
)