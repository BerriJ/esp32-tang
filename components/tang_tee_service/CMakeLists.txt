cmake_minimum_required(VERSION 3.16)

idf_build_get_property(esp_tee_build ESP_TEE_BUILD)

if(esp_tee_build)
    # TEE build: compile the service implementation
    idf_component_register(SRCS "tang_tee_service.c"
                           INCLUDE_DIRS include
                           PRIV_REQUIRES main nvs_flash)
else()
    # REE build: only expose the header (wrapper functions calling esp_tee_service_call)
    idf_component_register(INCLUDE_DIRS include
                           REQUIRES esp_tee)
endif()
