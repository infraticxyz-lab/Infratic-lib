// Result types for the extra RPC methods (see "MORE RPC METHODS" in Infratic-lib.h).
#ifndef INFRATIC_RPC_H
#define INFRATIC_RPC_H

#include <Arduino.h>
#include <vector>

/** Account as returned by getAccountInfo / getMultipleAccounts */
struct AccountInfo
{
    bool exists = false; // false when the RPC answered null (account not found)
    uint64_t lamports = 0;
    String owner;
    bool executable = false;
    uint64_t rentEpoch = 0;
    std::vector<uint8_t> data;
};

/** SPL token account (Token Program or Token-2022) from getTokenAccountsByOwner */
struct TokenAccount
{
    String address;
    String mint;
    String owner;
    uint64_t amount = 0; // raw amount (no decimals applied)
    uint8_t decimals = 0;
    String uiAmount; // amount as decimal string, e.g. "1.5"
    bool frozen = false;
};

/** One entry of getSignatureStatuses */
struct SignatureStatus
{
    bool found = false; // false when the cluster does not know the signature (null)
    uint64_t slot = 0;
    String confirmationStatus; // "processed", "confirmed", "finalized" (empty if unknown)
    bool failed = false;
    String err; // JSON of the transaction error, empty if none
};

/** Condensed getTransaction result */
struct TransactionInfo
{
    bool found = false; // false when the transaction is not (yet) available
    uint64_t slot = 0;
    int64_t blockTime = 0; // 0 if unknown
    uint64_t fee = 0;
    bool failed = false;
    String err; // JSON of the transaction error, empty if none
    std::vector<int64_t> preBalances;
    std::vector<int64_t> postBalances;
    std::vector<String> accountKeys; // static keys, then loaded writable / readonly (v0)
    std::vector<String> logs;
};

#endif
