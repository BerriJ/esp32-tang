{
  description = "ESP32 Tang Server Development Environment";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
    };
    nixpkgs.follows = "nixpkgs-esp-dev/nixpkgs";
    idf-extra-components = {
      url = "github:espressif/idf-extra-components";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      nixpkgs-esp-dev,
      idf-extra-components,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            permittedInsecurePackages = [
              "python3.13-ecdsa-0.19.1"
            ];
          };
          overlays = [ nixpkgs-esp-dev.overlays.default ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "esp32-tang-dev";

          buildInputs =
            with pkgs;
            [
              python3Packages.pandas

              # ESP-IDF with full toolchain
              esp-idf-full
              jose
              clevis

              # Development tools
              gnumake
              cmake
              ninja
              ccache

              # Serial communication tools
              picocom
              screen
              minicom

              # Development utilities
              curl
              wget
              unzip
              file
              which
              jq

              # Text processing tools
              gawk
              gnused
              gnugrep

              # Optional development tools
              clang-tools
              bear
            ]
            ++ lib.optionals stdenv.isLinux [
              # Linux-specific packages for USB device access
              udev
              libusb1
            ];

          shellHook = ''
            echo "🚀 ESP32 Tang Server Development Environment"
            echo "============================================="
            echo
            echo "ESP-IDF: $(idf.py --version 2>/dev/null || echo 'Ready')"
            echo "Python: $(python3 --version)"
            echo "CMake: $(cmake --version | head -1)"
            echo
            echo "Available commands:"
            echo "  📦 idf.py build         - Build the project"
            echo "  📡 idf.py flash         - Flash to device"
            echo "  💻 idf.py monitor       - Serial monitor"
            echo "  🔧 idf.py flash monitor - Flash and monitor"
            echo "  ⚙️  idf.py menuconfig   - Configuration menu"
            echo "  🎯 idf.py set-target    - Set target (esp32)"
            echo
            echo "Or use the Makefile shortcuts:"
            echo "  make setup-target      - Set ESP32 target"
            echo "  make build             - Build project"
            echo "  make flash-monitor     - Flash and monitor"
            echo "  make menuconfig        - Configuration"
            echo
            echo "Quick start:"
            echo "  1. Set target:         make setup-target"
            echo "  2. Configure:          make menuconfig"
            echo "  3. Build:              make build"
            echo "  4. Flash & Monitor:    make flash-monitor PORT=/dev/ttyUSB0"
            echo

            # Set up development environment
            export IDF_TOOLS_PATH="$HOME/.espressif"
            export CCACHE_DIR="$HOME/.ccache"

            # Provide real json_generator from Nix (needed for TEE attestation)
            _JG_NIX="${idf-extra-components}/json_generator"
            _JG_LOCAL="$PWD/components/json_generator"
            if [ -L "$_JG_LOCAL" ] || [ ! -e "$_JG_LOCAL/src" ]; then
              rm -rf "$_JG_LOCAL"
              ln -sf "$_JG_NIX" "$_JG_LOCAL"
            fi

            # Create necessary directories
            mkdir -p "$IDF_TOOLS_PATH"
            mkdir -p "$CCACHE_DIR"

            # Check for serial devices
            if ls /dev/ttyUSB* >/dev/null 2>&1; then
              echo "📡 Found USB serial devices:"
              ls -la /dev/ttyUSB* 2>/dev/null
            elif ls /dev/ttyACM* >/dev/null 2>&1; then
              echo "📡 Found ACM serial devices:"
              ls -la /dev/ttyACM* 2>/dev/null
            else
              echo "📡 No serial devices found. Connect your ESP32 board."
            fi

            # Check serial permissions
            if ! groups | grep -q dialout 2>/dev/null && ! groups | grep -q uucp 2>/dev/null; then
              echo
              echo "⚠️  Note: You may need to add your user to the 'dialout' group"
              echo "   to access serial devices:"
              echo "   sudo usermod -a -G dialout $USER"
              echo "   Then log out and log back in."
            fi

            echo
            echo "Ready for ESP32 development with Arduino support! 🎯"
            echo
          '';

          # allow /dev/ access
          extraDevPaths = [
            "/dev/ttyUSB*"
            "/dev/ttyACM*"
          ];

          # Environment variables
          IDF_TOOLS_PATH = "$HOME/.espressif";
          CCACHE_DIR = "$HOME/.ccache";

          # Disable IDF component manager — the TEE subproject's idf_component.yml
          # lives in the read-only Nix store. We provide json_generator via Nix instead.
          IDF_COMPONENT_MANAGER = "0";

          # Prevent Python from creating __pycache__ directories
          PYTHONDONTWRITEBYTECODE = "1";

          # Enable colored output
          FORCE_COLOR = "1";

          # Set locale to avoid issues
          LANG = "C.UTF-8";
          LC_ALL = "C.UTF-8";
        };

        devShells.minimal = pkgs.mkShell {
          name = "esp32-tang-minimal";

          buildInputs = with pkgs; [
            esp-idf-full
            picocom
          ];

          shellHook = ''
            echo "⚡ ESP32 Tang Server (Minimal Environment)"
            echo "========================================"
            echo "Ready for ESP32 development!"
            echo

            export IDF_TOOLS_PATH="$HOME/.espressif"
            export CCACHE_DIR="$HOME/.ccache"
            mkdir -p "$CCACHE_DIR"

            # Provide real json_generator from Nix (needed for TEE attestation)
            _JG_NIX="${idf-extra-components}/json_generator"
            _JG_LOCAL="$PWD/components/json_generator"
            if [ -L "$_JG_LOCAL" ] || [ ! -e "$_JG_LOCAL/src" ]; then
              rm -rf "$_JG_LOCAL"
              ln -sf "$_JG_NIX" "$_JG_LOCAL"
            fi
          '';

          # Disable IDF component manager for Nix compatibility
          IDF_COMPONENT_MANAGER = "0";

          extraDevPaths = [
            "/dev/ttyUSB*"
            "/dev/ttyACM*"
          ];
        };
      }
    );
}
