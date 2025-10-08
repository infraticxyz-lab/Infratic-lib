# Infratic 🚀

**Infratic** is a comprehensive C++ blockchain library for ESP32 microcontrollers, enabling direct interaction with the **Solana blockchain** and **Anchor framework** smart contracts.

[![Version](https://img.shields.io/badge/version-1.0.8-blue.svg)](https://github.com/infraticxyz-lab/Infratic-lib)
[![Platform](https://img.shields.io/badge/platform-ESP32-green.svg)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

**🌐 Website:** [**infratic.xyz**](https://infratic.xyz)  
**📚 Documentation:** [**docs.infratic.xyz**](https://docs.infratic.xyz)

---

## ✨ Features

### 🪙 Blockchain Operations
- ✅ Send SOL (native Solana transfers)
- ✅ SPL Token transfers with automatic ATA creation
- ✅ Get SOL and SPL token balances
- ✅ Fetch all token accounts for a wallet
- ✅ Transaction confirmation with retry logic

### 🔐 Cryptography & Security
- ✅ Ed25519 signing (pure C/C++, no external dependencies)
- ✅ Base58 encoding/decoding
- ✅ Message signing with Base58 or raw binary keys

### 🎯 Advanced Features
- ✅ PDA (Program Derived Address) derivation
- ✅ Associated Token Account (ATA) creation
- ✅ Anchor framework discriminator calculation
- ✅ Custom program instruction building
- ✅ Multi-instruction transactions

### 📡 RPC Support
- ✅ Full Solana JSON-RPC compatibility
- ✅ Blockchain queries (block height, epoch info, latest blockhash)
- ✅ Token metadata retrieval (decimals, supply)
- ✅ Automatic retry with exponential backoff

---

## 📦 Installation

### PlatformIO (Recommended)

Add to your `platformio.ini`:
```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
    asimbugra/Infratic@^1.0.8
    bblanchon/ArduinoJson@^6.21.5
    [https://github.com/rweather/arduinolibs.git](https://github.com/rweather/arduinolibs.git)
    [https://github.com/kmackay/micro-ecc.git](https://github.com/kmackay/micro-ecc.git)

build_flags =
    -UCONFIG_BT_ENABLED
    -UCONFIG_BLUEDROID_ENABLED
    -DCONFIG_BT_ENABLED=0
    -DCONFIG_BLUEDROID_ENABLED=0
    -DARDUINO_ARCH_ESP32
    -DED25519_NO_SEED
    -std=gnu++17
    -w

monitor_speed = 115200