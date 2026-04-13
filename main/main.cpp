/*
 * ESP32 Tang Server - Main Entry Point
 */
#include "TangServer.h"

extern "C" void app_main(void) {
  setup();

  while (true) {
    loop();
  }
}
