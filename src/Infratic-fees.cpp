// Priority fees with the Compute Budget program.
#include "infratic_internal.h"
#include <algorithm>

void Infratic::setPriorityFee(uint64_t microLamportsPerUnit, uint32_t computeUnitLimit)
{
    _priorityFeeMicroLamports = microLamportsPerUnit;
    _computeUnitLimit = computeUnitLimit;
}

Instruction Infratic::setComputeUnitLimitIx(uint32_t units)
{
    std::vector<uint8_t> data = {2};
    std::vector<uint8_t> u = encodeU32LE(units);
    data.insert(data.end(), u.begin(), u.end());
    return Instruction(Pubkey::fromBase58(INFRATIC_COMPUTE_BUDGET_PROGRAM_ID), {}, data);
}

Instruction Infratic::setComputeUnitPriceIx(uint64_t microLamportsPerUnit)
{
    std::vector<uint8_t> data = {3};
    std::vector<uint8_t> p = encodeU64LE(microLamportsPerUnit);
    data.insert(data.end(), p.begin(), p.end());
    return Instruction(Pubkey::fromBase58(INFRATIC_COMPUTE_BUDGET_PROGRAM_ID), {}, data);
}

void Infratic::applyPriorityFee(Transaction &tx) const
{
    if (_priorityFeeMicroLamports == 0 && _computeUnitLimit == 0)
    {
        return;
    }

    Pubkey budget = Pubkey::fromBase58(INFRATIC_COMPUTE_BUDGET_PROGRAM_ID);
    Pubkey system = Pubkey::fromBase58(INFRATIC_SYSTEM_PROGRAM_ID);
    size_t insertAt = 0;
    for (size_t i = 0; i < tx.instructions.size(); i++)
    {
        const Instruction &ix = tx.instructions[i];
        if (ix.programId.data == budget.data)
        {
            return; // caller already set a compute budget
        }
        // a durable nonce advance must stay the first instruction
        if (i == 0 && ix.programId.data == system.data && ix.data.size() == 4 && ix.data[0] == 4 &&
            ix.data[1] == 0 && ix.data[2] == 0 && ix.data[3] == 0)
        {
            insertAt = 1;
        }
    }

    std::vector<Instruction> extra;
    if (_computeUnitLimit > 0)
    {
        extra.push_back(setComputeUnitLimitIx(_computeUnitLimit));
    }
    if (_priorityFeeMicroLamports > 0)
    {
        extra.push_back(setComputeUnitPriceIx(_priorityFeeMicroLamports));
    }
    tx.instructions.insert(tx.instructions.begin() + insertAt, extra.begin(), extra.end());
}

bool Infratic::estimatePriorityFee(const std::vector<String> &writableAccounts, uint64_t &outMicroLamports,
                                   uint8_t percentile)
{
    String params = "[[";
    for (size_t i = 0; i < writableAccounts.size(); i++)
    {
        if (i) params += ",";
        params += "\"" + writableAccounts[i] + "\"";
    }
    params += "]]";

    String response;
    if (!rpcCall("getRecentPrioritizationFees", params, response))
    {
        return false;
    }

    DynamicJsonDocument doc(infratic_detail::jsonCapacity(response));
    if (deserializeJson(doc, response))
    {
        return false;
    }

    std::vector<uint64_t> fees;
    for (JsonObject item : doc["result"].as<JsonArray>())
    {
        fees.push_back(item["prioritizationFee"] | 0ULL);
    }
    if (fees.empty())
    {
        outMicroLamports = 0;
        return true;
    }

    std::sort(fees.begin(), fees.end());
    if (percentile > 100) percentile = 100;
    size_t idx = (fees.size() - 1) * percentile / 100;
    outMicroLamports = fees[idx];
    _logInfo.printf("💡 Suggested priority fee: %llu micro-lamports/CU\n", (unsigned long long)outMicroLamports);
    return true;
}
