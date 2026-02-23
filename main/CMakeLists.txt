idf_component_register(SRCS "main.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls esp-cryptoauthlib esp_http_server esp_wifi nvs_flash json esp_timer efuse)
