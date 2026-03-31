idf_component_register(SRCS "main.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls esp_http_server esp_https_server esp_wifi nvs_flash json esp_timer efuse esp_tee tang_tee_service
                       EMBED_TXTFILES "https_server.crt" "https_server.key")
