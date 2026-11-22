// Device signatures verified on chain by the native Ed25519 program.
#include "infratic_internal.h"

namespace
{
    bool isUtf8(const std::vector<uint8_t> &d)
    {
        size_t i = 0;
        while (i < d.size())
        {
            uint8_t c = d[i];
            size_t n = c < 0x80 ? 0 : (c >> 5) == 0x6 ? 1 : (c >> 4) == 0xE ? 2 : (c >> 3) == 0x1E ? 3 : 99;
            if (n == 99 || (c == 0 && n == 0) || i + n >= d.size() + (n ? 0 : 1)) return false;
            for (size_t k = 1; k <= n; k++)
                if (i + k >= d.size() || (d[i + k] >> 6) != 0x2) return false;
            i += n + 1;
        }
        return true;
    }

    void putU16(std::vector<uint8_t> &v, size_t at, uint16_t x)
    {
        v[at] = x & 0xFF;
        v[at + 1] = x >> 8;
    }
}

Instruction Infratic::ed25519VerifyIx(const Pubkey &signer, const uint8_t signature[64],
                                      const std::vector<uint8_t> &message)
{
    // header (16 bytes) | public key (32) | signature (64) | message
    const uint16_t HEADER = 16, PUBKEY_OFFSET = HEADER, SIG_OFFSET = PUBKEY_OFFSET + 32, MSG_OFFSET = SIG_OFFSET + 64;
    const uint16_t THIS_IX = 0xFFFF; // data lives in this instruction

    std::vector<uint8_t> data(MSG_OFFSET, 0);
    data[0] = 1; // number of signatures
    data[1] = 0; // padding
    putU16(data, 2, SIG_OFFSET);
    putU16(data, 4, THIS_IX);
    putU16(data, 6, PUBKEY_OFFSET);
    putU16(data, 8, THIS_IX);
    putU16(data, 10, MSG_OFFSET);
    putU16(data, 12, (uint16_t)message.size());
    putU16(data, 14, THIS_IX);
    if (signer.data.size() == 32)
    {
        memcpy(data.data() + PUBKEY_OFFSET, signer.data.data(), 32);
    }
    memcpy(data.data() + SIG_OFFSET, signature, 64);
    data.insert(data.end(), message.begin(), message.end());

    return Instruction(Pubkey::fromBase58(INFRATIC_ED25519_PROGRAM_ID), {}, data);
}

Instruction Infratic::ed25519SignIx(const Keypair &device, const std::vector<uint8_t> &message)
{
    uint8_t sig[64] = {0};
    if (device.privkey.size() >= 64)
    {
        Ed25519::sign(sig, device.privkey.data(), device.privkey.data() + 32, message.data(), message.size());
    }
    return ed25519VerifyIx(device.pubkey(), sig, message);
}

bool Infratic::verifySignature(const Pubkey &signer, const uint8_t signature[64], const std::vector<uint8_t> &message)
{
    return signer.data.size() == 32 && Ed25519::verify(signature, signer.data.data(), message.data(), message.size());
}

bool Infratic::sendSignedData(const Keypair &device, const Keypair &payer, const std::vector<uint8_t> &data,
                              String &outSignature)
{
    if (device.privkey.size() < 64 || payer.privkey.size() < 64)
    {
        _logErr.println("❌ sendSignedData: invalid keys");
        return false;
    }

    Transaction tx;
    tx.fee_payer = payer.pubkey();
    tx.add(ed25519SignIx(device, data));
    // the memo program only accepts UTF-8, binary data is written as hex
    std::vector<uint8_t> memo = data;
    if (!isUtf8(data))
    {
        static const char *hexd = "0123456789abcdef";
        memo.clear();
        for (uint8_t b : data)
        {
            memo.push_back(hexd[b >> 4]);
            memo.push_back(hexd[b & 15]);
        }
    }
    tx.add(Instruction(Pubkey::fromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), {}, memo));

    _logInfo.println("✍️  Device-signed data from " + device.publicBase58());
    std::vector<Keypair> signers = {payer};
    return signAndSend(tx, signers, outSignature);
}
