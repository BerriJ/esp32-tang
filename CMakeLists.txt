cmake_minimum_required(VERSION 3.16)

list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components/esp_tee/subproject/components/tee_sec_storage")

# Include ESP-IDF build system and custom TEE secure services
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/components/tang_tee_service/tee_project.cmake)

project(esp32-tang)