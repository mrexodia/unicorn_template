# Modern CMake
cmake_minimum_required(VERSION 3.18)

project(unicorn_template)

# Add module path for dependencies
list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Enable solution folder support
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_FOLDER "Dependencies")
include(CPM)
include(unicorn)
include(keystone)
include(capstone)

set(CMAKE_FOLDER "")

add_executable(${PROJECT_NAME}
    main.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    unicorn
    keystone
    capstone
)

target_compile_features(${PROJECT_NAME} PRIVATE
    cxx_std_17
)

# Set Visual Studio startup project
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})

# Tests
enable_testing()
add_test(NAME ${PROJECT_NAME} COMMAND "$<TARGET_FILE:unicorn_template>")