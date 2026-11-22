# Infratic 🚀

**Infratic** is a C++ blockchain library for ESP32 microcontrollers, enabling direct interaction with the **Solana blockchain** and **Anchor framework** smart contracts.

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/infraticxyz-lab/Infratic-lib)
[![Platform](https://img.shields.io/badge/platform-ESP32-green.svg)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

**🌐 Website:** [**infratic.xyz**](https://infratic.xyz)  
**📚 Documentation:** [**docs.infratic.xyz**](https://docs.infratic.xyz)

---

## ✨ Features

### 🪙 Blockchain Operations
- ✅ Send SOL (native Solana transfers)
- ✅ Send SPL tokens (Token Program and Token-2022), create ATAs automatically
- ✅ Get SOL and SPL token balances, token decimals
- ✅ Derive / find Associated Token Accounts
- ✅ Transaction confirmation with retry logic
- ✅ Priority fees (Compute Budget) on every transaction the library sends
- ✅ Durable nonce: sign now, send later (no 60 s blockhash limit)

### 🔐 Cryptography
- ✅ Ed25519 signing
- ✅ Base58 encoding/decoding
- ✅ Message signing with Base58 or raw binary keys

### 🎯 Programs & Transactions
- ✅ PDA (Program Derived Address) derivation, identical to `@solana/web3.js`
- ✅ Anchor discriminator calculation and Borsh helpers
- ✅ Custom instructions, multi-instruction and multi-signer transactions
- ✅ x402 escrow client (create, confirm delivery, release, cancel, dispute, force close)

### 📡 RPC
- ✅ Blockchain queries (block height, epoch info, latest blockhash, cluster time)
- ✅ Generic `rpcCall()` for any JSON-RPC method
- ✅ `getAccountData`, `getProgramAccounts` (with `dataSize` / `memcmp` filters), `getSignaturesForAddress`
- ✅ `getMinimumBalanceForRentExemption`

---

## 📦 Installation

### PlatformIO (Recommended)

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
    asimbugra/Infratic@^1.1.0
    bblanchon/ArduinoJson@^6.21.5

build_flags =
    -std=gnu++17

build_unflags = -std=gnu++11

monitor_speed = 115200
```

`rweather/Crypto` (Ed25519) is installed automatically as a dependency. You don't need to add `arduinolibs` or `micro-ecc` anymore.

To use the latest code from GitHub:

```ini
lib_deps =
    https://github.com/infraticxyz-lab/Infratic-lib.git
    bblanchon/ArduinoJson@^6.21.5
```

### Arduino IDE

Install **Infratic**, **ArduinoJson (6.x)** and **Crypto** from the Library Manager.

---

## 🚀 Quick Start

```cpp
#include <WiFi.h>
#include "Infratic-lib.h"

Infratic solana("https://api.devnet.solana.com");

void setup() {
    Serial.begin(115200);
    WiFi.begin("SSID", "PASSWORD");
    while (WiFi.status() != WL_CONNECTED) delay(500);

    uint64_t lamports = 0;
    if (solana.getSolBalance("YOUR_PUBKEY", lamports)) {
        Serial.printf("Balance: %llu lamports\n", lamports);
    }
}

void loop() {}
```

### Logging

The library prints progress to `Serial`. You can reduce it:

```cpp
Infratic::setLogLevel(INFRATIC_LOG_ERROR); // only errors
Infratic::setLogLevel(INFRATIC_LOG_NONE);  // silent
```

---

## 🧩 Anchor Instructions

```cpp
// PDA with a u64 seed (Rust: id.to_be_bytes())
String pda; uint8_t bump;
solana.derivePDA({{'r','e','q','u','e','s','t'}, encodeU64BE(requestId)}, PROGRAM_ID, pda, bump);

// instruction data: discriminator + Borsh args
std::vector<uint8_t> data = solana.calculateDiscriminator("fulfill_request");
appendBorshString(data, "payload");

Instruction ix(Pubkey::fromBase58(PROGRAM_ID), {
    AccountMeta{Pubkey::fromBase58(configPda), false, false}, // readonly
    AccountMeta::writable(Pubkey::fromBase58(pda)),           // writable
    AccountMeta::signer(node.pubkey()),                       // signer
}, data);

Transaction tx;
tx.fee_payer = node.pubkey();
tx.recent_blockhash = solana.getLatestBlockhash();
tx.add(ix);
tx.sign({node});              // pass every required signer

String sig;
solana.sendRawTransaction(tx.serializeBase64(), sig);
```

Accounts are ordered and flagged the way the Solana runtime expects, lengths use compact-u16, so instruction data longer than 127 bytes and multiple signers work.

### Reading accounts

```cpp
std::vector<ProgramAccount> accounts;
solana.getProgramAccounts(PROGRAM_ID, {
    AccountFilter::dataSize(300),
    AccountFilter::memcmp(8, encodeU64LE(requestId))
}, accounts);

std::vector<uint8_t> raw;
solana.getAccountData(accountAddress, raw);
```

Use filters on ESP32: an unfiltered `getProgramAccounts` response can easily be larger than the available RAM.

---

## ⚡ Priority Fees

When the network is busy, transactions without a priority fee are often dropped.

```cpp
uint64_t fee;
if (solana.estimatePriorityFee({}, fee, 75)) {   // 75th percentile of recent slots
    solana.setPriorityFee(fee, 200000);          // micro-lamports per CU, CU limit
}
// every transaction the library builds now includes the compute budget instructions
```

For your own transactions call `solana.applyPriorityFee(tx)` before signing, or add `Infratic::setComputeUnitLimitIx` / `setComputeUnitPriceIx` yourself.

---

## 🔒 Durable Nonce

A normal transaction must reach the network within ~60 seconds of fetching the blockhash. With a durable nonce a device can sign a transaction now and send it whenever it is online.

```cpp
// once: create a nonce account controlled by the device wallet
Keypair nonceKp = Keypair::generate();          // save nonceKp.secretBase58() somewhere safe
solana.createNonceAccount(PRIVATE_KEY, nonceKp, MY_PUBKEY, sig);

// later: build any transaction and make it durable
Transaction tx;
tx.add(/* your instructions */);
solana.useDurableNonce(tx, nonceKp.publicBase58(), MY_PUBKEY);
solana.signAndSend(tx, {myKeypair}, sig);       // the nonce advances when it lands
```

---

## 💸 SPL Tokens

```cpp
String sig;
// 1.5 USDC (6 decimals) - the recipient ATA is created if missing
solana.sendSplToken(PRIVATE_KEY, MY_PUBKEY, RECIPIENT_PUBKEY, USDC_MINT, 1500000, sig);

// Token-2022 mint, decimals known
solana.sendSplToken(PRIVATE_KEY, MY_PUBKEY, RECIPIENT_PUBKEY, MINT, 42, sig, 0, true,
                    INFRATIC_TOKEN_2022_PROGRAM_ID);

String ata;
solana.getAssociatedTokenAddress(OWNER, MINT, ata); // no RPC call
```

`createAssociatedTokenAccountIdempotentIx` and `transferCheckedIx` return plain instructions, so they can be combined with your own instructions in one `Transaction` and sent with `signAndSend`.

---

## 🤝 x402 Escrow

```cpp
solana.setEscrowProgramId("3kk7vGfWwT7Uq7M6uV5cfSyXodbsr7Py6gmBYDCMvstQ");

EscrowCreateResult created = solana.escrow_create(
    BUYER_PRIVATE_KEY, BUYER_PUBKEY, SELLER_PUBKEY,
    250000000,        // lamports
    "order-0001",     // order id (max 32 bytes, used as PDA seed)
    3600);            // expiration in seconds

EscrowAccountResult info = solana.getEscrowAccount(created.escrowPDA, "confirmed");

solana.escrow_confirmDelivery(SELLER_PRIVATE_KEY, SELLER_PUBKEY, created.escrowPDA, "proof-hash");
solana.escrow_release(BUYER_PRIVATE_KEY, BUYER_PUBKEY, SELLER_PUBKEY, created.escrowPDA);
```

Other calls: `escrow_cancel` (after expiration, checked with cluster time), `escrow_initiateDispute`, `escrow_forceClose`, `deriveEscrowPDA`.

---

## 🔏 Proof Helpers (ZK)

`createDataCommitment`, Merkle tree proofs, range proofs, timestamped proofs and batch commitments are hash based commitment helpers.

> ⚠️ `createzkSNARKProof` / `verifyzkSNARKProof` are **simplified placeholders**, not real zkSNARKs. They don't provide zero-knowledge or soundness guarantees. Use circom/snarkjs (or similar) for production proofs.

---

## 🧪 Tests

The library can be tested on a computer without an ESP32. The host tests build the library against Arduino stubs and compare PDAs, transactions, signatures and escrow decoding with `@solana/web3.js`:

```bash
cd test/host
(cd js && npm install && node gen.mjs > ../vectors.json)   # optional, vectors are committed
./build.sh
```

---

## 📝 Changelog

### 1.1.0
- Fixed PDA derivation: off-curve check was missing, bumps other than 255 were wrong
- Fixed transaction serialization: account ordering/header, compact-u16 lengths, multiple signers
- `Transaction::sign` no longer needs a global `Infratic solana` object
- Added x402 escrow client
- Added `rpcCall`, `getAccountData`, `getProgramAccounts`, `getSignaturesForAddress`, `getMinimumBalanceForRentExemption`, `getClusterTime`
- Added `encodeU64BE`, `encodeU32LE`, `encodeI64LE`, `appendCompactU16`, `appendBorshString`, `Infratic::isOnCurve`
- Added `Infratic::setLogLevel`
- mbedtls 3 (arduino-esp32 3.x) compatibility
- Fixed `library.json` file name, dependencies (`rweather/Crypto`)

---

## 📄 License

MIT
