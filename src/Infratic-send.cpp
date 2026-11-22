// Reliable sending: simulate, re-send until confirmed, error decoding.
#include "infratic_internal.h"

namespace
{
    // "...Error Code: X. Error Number: N. Error Message: M." (Anchor log format)
    bool parseAnchorLog(const String &line, TxError &out)
    {
        int code = line.indexOf("Error Code: ");
        int number = line.indexOf(". Error Number: ");
        int message = line.indexOf(". Error Message: ");
        if (code < 0 || number < 0 || message < 0 || line.indexOf("AnchorError") < 0)
        {
            return false;
        }
        out.name = line.substring(code + 12, number);
        out.customCode = line.substring(number + 16, message).toInt();
        String msg = line.substring(message + 17);
        if (msg.endsWith("."))
        {
            msg = msg.substring(0, msg.length() - 1);
        }
        out.message = msg;
        return true;
    }
}

void infratic_detail::parseTxError(JsonVariantConst err, JsonVariantConst logs, TxError &out)
{
    out = TxError();
    out.hasError = true;
    serializeJson(err, out.raw);

    if (err.is<const char *>())
    {
        out.name = err.as<const char *>(); // e.g. "BlockhashNotFound"
    }
    else if (!err["InstructionError"].isNull())
    {
        out.instructionIndex = err["InstructionError"][0] | -1;
        JsonVariantConst detail = err["InstructionError"][1];
        if (detail.is<const char *>())
        {
            out.name = detail.as<const char *>(); // e.g. "InvalidAccountData"
        }
        else if (!detail["Custom"].isNull())
        {
            out.customCode = detail["Custom"].as<long long>();
            out.name = "Custom";
        }
        else
        {
            for (JsonPairConst kv : detail.as<JsonObjectConst>())
            {
                out.name = kv.key().c_str();
                break;
            }
        }
    }
    else if (err.is<JsonObjectConst>())
    {
        for (JsonPairConst kv : err.as<JsonObjectConst>())
        {
            out.name = kv.key().c_str(); // e.g. InsufficientFundsForRent
            break;
        }
    }

    if (logs.is<JsonArrayConst>())
    {
        for (JsonVariantConst l : logs.as<JsonArrayConst>())
        {
            String line = l.as<const char *>() ? l.as<const char *>() : "";
            out.logs.push_back(line);
            TxError anchor;
            if (parseAnchorLog(line, anchor))
            {
                out.name = anchor.name;
                out.message = anchor.message;
                if (out.customCode < 0)
                {
                    out.customCode = anchor.customCode;
                }
            }
        }
    }
}

bool Infratic::getLatestBlockhash(String &outBlockhash, uint64_t &outLastValidBlockHeight)
{
    String response;
    for (int attempt = 0; attempt < 3; attempt++)
    {
        if (rpcCall("getLatestBlockhash", R"([{"commitment":"confirmed"}])", response))
        {
            DynamicJsonDocument doc(1024);
            if (!deserializeJson(doc, response))
            {
                outBlockhash = doc["result"]["value"]["blockhash"] | "";
                outLastValidBlockHeight = doc["result"]["value"]["lastValidBlockHeight"] | 0ULL;
                if (!outBlockhash.isEmpty())
                {
                    return true;
                }
            }
        }
        delay(500);
    }
    _logErr.println("❌ Failed to get blockhash");
    return false;
}

bool Infratic::simulateTransaction(const String &txBase64, SimulationResult &outResult, bool sigVerify)
{
    outResult = SimulationResult();
    String response;
    String params = "[\"" + txBase64 + R"(",{"encoding":"base64","commitment":"confirmed","sigVerify":)" +
                    (sigVerify ? "true" : "false") + "}]";
    if (!rpcCall("simulateTransaction", params, response))
    {
        return false;
    }

    DynamicJsonDocument doc(infratic_detail::jsonCapacity(response));
    if (deserializeJson(doc, response))
    {
        return false;
    }

    JsonVariant value = doc["result"]["value"];
    outResult.unitsConsumed = value["unitsConsumed"] | 0ULL;
    for (JsonVariant l : value["logs"].as<JsonArray>())
    {
        outResult.logs.push_back(l.as<String>());
    }

    if (value["err"].isNull())
    {
        outResult.success = true;
        _logInfo.printf("🧪 Simulation ok, %llu compute units\n", (unsigned long long)outResult.unitsConsumed);
    }
    else
    {
        infratic_detail::parseTxError(value["err"], value["logs"], outResult.error);
        _lastTxError = outResult.error;
        _logErr.println("❌ Simulation failed: " + outResult.error.name + " " + outResult.error.message);
    }
    return true;
}

bool Infratic::sendAndConfirm(const String &txBase64, uint64_t lastValidBlockHeight, String &outSignature,
                              uint32_t timeoutMs)
{
    const uint32_t resendIntervalMs = 2000;
    const uint32_t pollIntervalMs = 500;

    _lastTxError = TxError();
    if (!sendRawTransaction(txBase64, outSignature))
    {
        return false; // preflight error, see lastTxError()
    }

    unsigned long start = millis();
    unsigned long lastSend = start;
    while (millis() - start < timeoutMs)
    {
        int status = checkSignatureStatus(outSignature);
        if (status == 1)
        {
            _logInfo.println("✅ Transaction confirmed");
            return true;
        }
        if (status < 0)
        {
            return false;
        }

        if (millis() - lastSend >= resendIntervalMs)
        {
            if (lastValidBlockHeight > 0)
            {
                uint64_t height = 0;
                if (getBlockHeight(height) && height > lastValidBlockHeight)
                {
                    _lastTxError = TxError();
                    _lastTxError.hasError = true;
                    _lastTxError.name = "BlockhashExpired";
                    _lastTxError.message = "Blockhash expired before the transaction landed";
                    _logErr.println("❌ Blockhash expired, transaction was not included");
                    return false;
                }
            }
            String ignored;
            sendRawTransaction(txBase64, ignored, true); // re-broadcast, errors are expected here
            lastSend = millis();
        }
        delay(pollIntervalMs);
    }

    _lastTxError = TxError();
    _lastTxError.hasError = true;
    _lastTxError.name = "Timeout";
    _lastTxError.message = "Transaction not confirmed in time";
    _logErr.println("⏱️ Timeout: Transaction not confirmed");
    return false;
}
