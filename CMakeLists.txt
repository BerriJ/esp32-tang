# Top-level CMakeLists.txt for ESP32 Tang Server
cmake_minimum_required(VERSION 3.16)

# Set the project name
set(PROJECT_NAME "esp32-tang")

set(ENV{IDF_COMPONENT_MANAGER} "1")

# tee_sec_storage lives outside the default component search paths; must be
# set here (top-level CMakeLists.txt, before project()) since EXTRA_COMPONENT_DIRS
# has no effect when set from a component-level CMakeLists.txt (e.g. main/CMakeLists.txt)
list(APPEND EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/components/esp_tee/subproject/components/tee_sec_storage")

# Include ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Register custom TEE secure services (must be before project())
include(${CMAKE_CURRENT_LIST_DIR}/components/tang_tee_service/tee_project.cmake)

# Define the project
project(${PROJECT_NAME})
