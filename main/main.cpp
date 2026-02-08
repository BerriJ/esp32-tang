/*
 * ESP32 Tang Server - Main Entry Point
 */
#include <Arduino.h>
#include "TangServer.h"

#if !CONFIG_AUTOSTART_ARDUINO

extern "C" void app_main(void)
{
  initArduino();
  setup();

  while (true)
  {
    loop();
    vTaskDelay(1 / portTICK_PERIOD_MS);
  }
}

#endif
