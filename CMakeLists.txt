# Top-level CMakeLists.txt for ESP32 Tang Server
cmake_minimum_required(VERSION 3.16)

# Set the project name
set(PROJECT_NAME "esp32-tang")

# Disable IDF component manager — the TEE subproject's idf_component.yml
# lives in the read-only Nix store and the component manager tries to write
# there. We provide json_generator via Nix instead (see flake.nix).
# The flake.nix devShell sets IDF_COMPONENT_MANAGER=0 as an environment
# variable for the build-time subprocess; this line covers cmake configure.
set(ENV{IDF_COMPONENT_MANAGER} "0")

# Include ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Register custom TEE secure services (must be before project())
include(${CMAKE_CURRENT_LIST_DIR}/components/tang_tee_service/tee_project.cmake)

# Define the project
project(${PROJECT_NAME})
