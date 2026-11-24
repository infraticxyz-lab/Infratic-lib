# Infratic 🚀

**Infratic** is a C++ blockchain library for ESP32 microcontrollers, enabling direct interaction with the **Solana blockchain** and **Anchor framework** smart contracts.

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](https://github.com/infraticxyz-lab/Infratic-lib)
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
- ✅ Reliable sending: re-broadcast until confirmed, blockhash expiry detection, simulation
- ✅ Readable errors: instruction errors and Anchor error codes via `lastTxError()`
- ✅ Priority fees (Compute Budget) on every transaction the library sends
- ✅ Durable nonce: sign now, send later (no 60 s blockhash limit)

### 🔐 Cryptography & Keys
- ✅ BIP39 mnemonics (12/24 words) with Phantom/Solflare compatible derivation
- ✅ PIN protected key storage on the device (AES-256-GCM in NVS, wipe after wrong PINs)
- ✅ Ed25519 signing
- ✅ Device signatures verified on chain (Ed25519 program) for signed sensor data
- ✅ Base58 encoding/decoding
- ✅ Message signing with Base58 or raw binary keys

### 🎯 Programs & Transactions
- ✅ PDA (Program Derived Address) derivation, identical to `@solana/web3.js`
- ✅ Anchor discriminators, `BorshReader` / `BorshWriter`
- ✅ Anchor events (`emit!`) from transaction logs or live log subscriptions
- ✅ Custom instructions, multi-instruction and multi-signer transactions
- ✅ Versioned transactions (v0) with Address Lookup Tables
- ✅ x402 escrow client (create, confirm delivery, release, cancel, dispute, force close)

### 📡 RPC & Subscriptions
- ✅ WebSocket subscriptions: account, program (with filters), logs and signature notifications
- ✅ Blockchain queries (block height, epoch info, latest blockhash, cluster time)
- ✅ Generic `rpcCall()` for any JSON-RPC method
- ✅ `getAccountData`, `getProgramAccounts` (with `dataSize` / `memcmp` filters), `getSignaturesForAddress`
- ✅ `getMinimumBalanceForRentExemption`
- ✅ Low power flow: fast WiFi reconnect after deep sleep, persistent data queue, RPC timeouts
- ✅ RPC failover: backup endpoints, switch on connection errors, 429 and 5xx
- ✅ Verified TLS: server certificates are checked against built-in root CAs of the common RPC providers

---

## 📦 Installation

### PlatformIO (Recommended)

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
    asimbugra/Infratic@^1.3.0
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

## 🔑 On-Device Wallet Keys

Generate the wallet on the device, back it up as 12/24 words, keep it encrypted with a PIN.

```cpp
KeyStore store("wallet");
if (!store.exists()) {
    String words = Mnemonic::generate(24);   // show once for backup
    store.saveMnemonic(words, "4821");
}

Keypair wallet;
if (store.unlock("4821", wallet)) {          // account 0 -> same address as in Phantom
    Serial.println(wallet.publicBase58());
}
```

The secret is encrypted with AES-256-GCM using a key derived from the PIN (PBKDF2-HMAC-SHA256, 20000 rounds). After 10 wrong PINs the slot is wiped (`setMaxAttempts`). For production devices also enable ESP32 flash encryption so the NVS partition can't be read from a flash dump.

---

## ✍️ Device Signatures

Sign data with a device key and let the Ed25519 program verify it on chain. The device key never pays fees, a separate payer signs the transaction.

```cpp
Keypair device;                                   // e.g. from KeyStore
Keypair payer = Keypair::fromBase58(PAYER_KEY);

String json = "{\"t\":23.4,\"h\":51}";
std::vector<uint8_t> data(json.begin(), json.end());
String sig;
sol.sendSignedData(device, payer, data, sig);     // ed25519 verify ix + memo with the data
```

For your own program, add `Infratic::ed25519SignIx(device, data)` before your instruction and read it from the instructions sysvar (`INFRATIC_SYSVAR_INSTRUCTIONS_ID`). `Infratic::verifySignature()` checks a signature locally.

---

## 🔋 Low Power

Wake up, measure, queue the reading, send a batch every few wakes, sleep again.

```cpp
DataQueue queue("temp", 32);              // kept in NVS, survives sleep and power loss

void setup() {
    uint32_t boot = LowPower::begin();    // 1 = cold boot
    queue.push(String(readTemperature(), 1));

    if (boot % 10 == 0) {
        if (LowPower::connectWiFi(SSID, PASS, 8000)) {   // reuses channel + BSSID, skips the scan
            sol.setTimeout(5000);
            String batch;
            std::vector<uint8_t> v;
            for (uint16_t i = 0; i < queue.size() && queue.peek(i, v); i++)
                batch += String((const char *)v.data(), v.size()) + ";";
            std::vector<uint8_t> data(batch.begin(), batch.end());
            String sig;
            if (sol.sendSignedData(device, payer, data, sig)) queue.clear();
        }
    }
    LowPower::sleep(60);                  // radio off, deep sleep, setup() runs again
}
```

When the queue is full the oldest entry is dropped. The WiFi cache lives in RTC memory, so it is gone after a power loss and the next connect scans once.

---

## 🔀 RPC Failover

```cpp
Infratic sol("https://mainnet.helius-rpc.com/?api-key=...");
sol.addRpcEndpoint("https://api.mainnet-beta.solana.com");
sol.addRpcEndpoint("https://solana-rpc.publicnode.com");
```

If the active endpoint has a connection or TLS error, returns 429 or 5xx, the same request goes to the next one, which then stays active. After 5 minutes the primary is tried again (`setPrimaryRetryInterval`). RPC errors (bad params, failed simulation) are not retried. WebSocket connects to the active endpoint and moves on when it can't connect, unless `setWsUrl()` was set. `activeRpcUrl()` shows the endpoint in use.

---

## 🔐 TLS Verification

HTTPS and WSS connections verify the server certificate. The library ships the root CAs used by api.*.solana.com, Helius, QuickNode, Alchemy, Ankr, dRPC, PublicNode and Shyft, so nothing needs to be configured for these.

```cpp
sol.setRootCA(MY_PROVIDER_ROOT_PEM);   // other provider: one or more PEM certificates
sol.setTlsInsecure();                  // local tests only, skips verification
```

`http://` URLs (e.g. a local `solana-test-validator`) are used without TLS.

---

## 🛡️ Reliable Sending & Errors

`signAndSend` (and everything built on it) re-sends the transaction every ~2 s until it is confirmed, fails, or its blockhash expires.

```cpp
if (!solana.signAndSend(tx, {myKeypair}, sig)) {
    const TxError &e = solana.lastTxError();
    // e.name: "InsufficientRequestCredits", "BlockhashExpired", "InvalidAccountData", ...
    // e.customCode: Anchor error number (6000+), e.instructionIndex, e.message, e.logs
}

SimulationResult sim;                       // dry run before spending fees
solana.simulateTransaction(tx.serializeBase64(), sim);
Serial.printf("units: %llu ok: %d\n", sim.unitsConsumed, sim.success);
```

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

## 📡 WebSocket Subscriptions

Get notified the moment something changes instead of polling every few seconds.

```cpp
solana.onProgramAccountChange([](int handle, const String &pubkey, const std::vector<uint8_t> &data, uint64_t slot) {
    Serial.println("account changed: " + pubkey);
});
solana.onLogs([](int handle, const String &sig, const std::vector<String> &logs, bool failed, uint64_t slot) {
    Serial.println("tx: " + sig);
});

solana.programSubscribe(PROGRAM_ID, {AccountFilter::dataSize(622)});
solana.logsSubscribe(PROGRAM_ID);

void loop() {
    solana.wsLoop();   // reads messages, runs callbacks, pings, reconnects
}
```

The WebSocket URL is derived from the RPC URL (`https://` → `wss://`), or set it with `setWsUrl`. After a reconnect all subscriptions are restored and keep their handles. Messages larger than `setWsMaxMessageSize` (default 64 KB) are rejected to protect RAM.

---

## 📇 Versioned Transactions & Lookup Tables

Programs that touch many accounts need v0 transactions: accounts listed in a lookup table cost 1 byte instead of 32.

```cpp
AddressLookupTable table;
solana.getAddressLookupTable(TABLE_ADDRESS, table);

Transaction tx;
tx.version = 0;
tx.lookupTables.push_back(table);
tx.add(/* instructions with many accounts */);
solana.signAndSend(tx, {myKeypair}, sig);
```

Create your own table with `createLookupTableIx` and fill it with `extendLookupTableIx`.

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

## 🧱 Instruction Builders

Static builders that return plain `Instruction` objects (no RPC) for the System program, SPL Token / Token-2022, the Associated Token program and the Memo program. Mix them freely in one `Transaction`. Accounts and data are byte-identical to `@solana/web3.js` and `@solana/spl-token` (checked by the host tests).

```cpp
Pubkey token = Pubkey::fromBase58(INFRATIC_TOKEN_2022_PROGRAM_ID); // or INFRATIC_TOKEN_PROGRAM_ID

Transaction tx;
tx.add(SystemProgram::createAccountIx(payer, mintKey, rentLamports, 82, token));
tx.add(SplToken::initializeMint2Ix(mintKey, 6, payer, nullptr, token));     // nullptr = no freeze authority
tx.add(SplToken::mintToCheckedIx(mintKey, destAta, payer, 1000000, 6, token));
tx.add(MemoProgram::memoIx("minted from an ESP32"));
solana.signAndSend(tx, {payerKeypair, mintKeypair}, sig);

String addr; // seed accounts: sha256(base || seed || program), seed up to 32 bytes
SystemProgram::createWithSeed(base, "vault", owner, addr);

// Wrapped SOL: creates the wSOL ATA if needed, transfers and syncs / closes it again
solana.wrapSol(keypair, 50000000, sig);   // 0.05 SOL
solana.unwrapSol(keypair, sig);
```

| Class | Builders |
|---|---|
| `SystemProgram` | `transferIx`, `createAccountIx`, `assignIx`, `allocateIx`, `createAccountWithSeedIx`, `transferWithSeedIx`, `createWithSeed` |
| `SplToken` | `initializeMint2Ix`, `initializeAccount3Ix`, `transferIx`, `mintToIx`, `mintToCheckedIx`, `burnIx`, `burnCheckedIx`, `approveIx`, `approveCheckedIx`, `revokeIx`, `closeAccountIx`, `setAuthorityIx` (`AuthorityType`, `nullptr` removes the authority), `syncNativeIx`, `freezeAccountIx`, `thawAccountIx`, `createAssociatedTokenAccountIx` |
| `MemoProgram` | `memoIx(text, signers)` |

Every `SplToken` builder takes the token program id last, so the same code serves Token and Token-2022. Multisig owners are not supported (single signer only).

---

## 🏷️ Token names and logos

```cpp
TokenMetadata meta;
if (solana.getTokenMetadata(USDC_MINT, meta) && meta.found) {
    Serial.println(meta.symbol);   // "USDC"
    Serial.println(meta.name);     // "USD Coin"
    Serial.println(meta.uri);      // off-chain JSON with the "image" (logo) URL
    Serial.println(meta.source);   // "metaplex" or "token-2022"
}
```

`getTokenMetadata` reads the mint, uses the Token-2022 metadata extension when the mint has one and otherwise the Metaplex Token Metadata account (one or two `getAccountInfo` calls). It returns `false` if the mint cannot be read; `meta.found` is `false` for a mint without metadata. Padding NULs of Metaplex strings are removed, and `decimals`, `updateAuthority` and `isMutable` are filled in as well.

For the full records use the offline parsers on raw account data: `TokenMetadataParser::parseMetaplex()` (creators, collection, uses, token standard, ...) and `TokenMetadataParser::parseToken2022()` (MetadataPointer, TokenMetadata and `additional_metadata`). `getMetadataPda` and `getMasterEditionPda` derive the Metaplex addresses without an RPC call. The parsers check every bound and ignore unknown trailing data.

---

## 📣 Anchor Events

```cpp
std::vector<String> logs;
solana.getTransactionLogs(signature, logs);          // or the logs from an onLogs callback

std::vector<AnchorEvent> events;
Infratic::parseAnchorEvents(logs, events, PROGRAM_ID);
for (const AnchorEvent &ev : events) {
    if (ev.is("RequestFulfilled")) {
        BorshReader r = ev.reader();                 // fields in Rust struct order
        uint64_t requestId = r.u64();
        String node = r.pubkey();
        String data = r.str();
    }
}

// instruction arguments
BorshWriter args;
args.u64(42).str("hello").pubkey(SOME_PUBKEY);
std::vector<uint8_t> ixData = solana.calculateDiscriminator("my_instruction");
ixData.insert(ixData.end(), args.data.begin(), args.data.end());
```

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

### 1.3.0
- On-device keys: BIP39 mnemonics, Phantom compatible derivation, PIN protected `KeyStore`
- Device signatures: `ed25519SignIx`, `sendSignedData`, `verifySignature`
- TLS certificate verification with built-in root CAs, `setRootCA`, `setTlsInsecure`
- Low power: `LowPower` (fast reconnect, deep sleep, boot counter), `DataQueue`, `setTimeout`
- RPC failover: `addRpcEndpoint`, `activeRpcUrl`

### 1.2.0
- SPL token transfers (`sendSplToken`, `transferCheckedIx`), ATA derivation and idempotent creation, Token-2022
- Priority fees: `setPriorityFee`, `estimatePriorityFee`, compute budget instructions
- Durable nonce: `createNonceAccount`, `getNonce`, `useDurableNonce`; `Keypair::generate` / `fromSeed`
- Reliable sending: `signAndSend` re-broadcasts until confirmed, blockhash expiry, `simulateTransaction`, `lastTxError()` with Anchor error decoding
- WebSocket subscriptions: account, program, logs, signature; auto reconnect
- Anchor events (`parseAnchorEvents`, `getTransactionLogs`), public `BorshReader` / `BorshWriter`
- Versioned transactions (v0) and Address Lookup Tables

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
