// On-device keys: BIP39 mnemonics, SLIP-0010 derivation and PIN protected storage.
#include "infratic_internal.h"
#include "bip39_english.h"
#include <Preferences.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/version.h>

#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 3
#define INFRATIC_SHA256_ONESHOT mbedtls_sha256
#else
#define INFRATIC_SHA256_ONESHOT mbedtls_sha256_ret
#endif

namespace
{
    const char *KS_NAMESPACE = "infratic_ks";
    const uint8_t KS_VERSION = 1;
    const uint8_t KS_TYPE_SEED = 0;
    const uint8_t KS_TYPE_MNEMONIC = 1;

    void wipeBytes(void *p, size_t n)
    {
        volatile uint8_t *v = (volatile uint8_t *)p;
        while (n--) *v++ = 0;
    }

    void randomBytes(uint8_t *out, size_t n)
    {
        for (size_t i = 0; i < n; i += 4)
        {
            uint32_t r = esp_random();
            for (size_t j = 0; j < 4 && i + j < n; j++) out[i + j] = (uint8_t)(r >> (8 * j));
        }
    }

    // word i of the packed wordlist
    String wordAt(int index)
    {
        const char *p = BIP39_ENGLISH;
        for (int i = 0; i < index && *p; i++)
        {
            while (*p && *p != ' ') p++;
            if (*p) p++;
        }
        const char *e = p;
        while (*e && *e != ' ') e++;
        return String(p, (unsigned)(e - p));
    }

    int indexOfWord(const String &word)
    {
        const char *p = BIP39_ENGLISH;
        for (int i = 0; *p; i++)
        {
            const char *e = p;
            while (*e && *e != ' ') e++;
            if ((size_t)(e - p) == word.length() && strncmp(p, word.c_str(), e - p) == 0) return i;
            p = *e ? e + 1 : e;
        }
        return -1;
    }

    std::vector<String> splitWords(const String &mnemonic)
    {
        std::vector<String> words;
        String cur;
        for (unsigned i = 0; i < mnemonic.length(); i++)
        {
            char c = mnemonic.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            {
                if (!cur.isEmpty()) words.push_back(cur);
                cur = "";
            }
            else
            {
                cur += (char)tolower(c);
            }
        }
        if (!cur.isEmpty()) words.push_back(cur);
        return words;
    }

    bool pbkdf2(mbedtls_md_type_t md, const uint8_t *pw, size_t pwLen, const uint8_t *salt, size_t saltLen,
                uint32_t iterations, uint8_t *out, size_t outLen)
    {
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md);
        if (!info || iterations == 0) return false;
        size_t hlen = mbedtls_md_get_size(info);

        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, info, 1) != 0 || mbedtls_md_hmac_starts(&ctx, pw, pwLen) != 0)
        {
            mbedtls_md_free(&ctx);
            return false;
        }

        uint8_t u[64], t[64];
        uint32_t block = 1;
        bool ok = true;
        while (outLen > 0 && ok)
        {
            uint8_t be[4] = {(uint8_t)(block >> 24), (uint8_t)(block >> 16), (uint8_t)(block >> 8), (uint8_t)block};
            ok = mbedtls_md_hmac_reset(&ctx) == 0 && mbedtls_md_hmac_update(&ctx, salt, saltLen) == 0 &&
                 mbedtls_md_hmac_update(&ctx, be, 4) == 0 && mbedtls_md_hmac_finish(&ctx, u) == 0;
            memcpy(t, u, hlen);
            for (uint32_t i = 1; i < iterations && ok; i++)
            {
                ok = mbedtls_md_hmac_reset(&ctx) == 0 && mbedtls_md_hmac_update(&ctx, u, hlen) == 0 &&
                     mbedtls_md_hmac_finish(&ctx, u) == 0;
                for (size_t j = 0; j < hlen; j++) t[j] ^= u[j];
            }
            size_t n = outLen < hlen ? outLen : hlen;
            memcpy(out, t, n);
            out += n;
            outLen -= n;
            block++;
        }
        wipeBytes(u, sizeof(u));
        wipeBytes(t, sizeof(t));
        mbedtls_md_free(&ctx);
        return ok;
    }

    bool hmacSha512(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[64])
    {
        return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), key, keyLen, data, len, out) == 0;
    }
}

// ----------------------------------------------------------------------------
// Mnemonic
// ----------------------------------------------------------------------------

bool Mnemonic::fromEntropy(const std::vector<uint8_t> &entropy, String &outMnemonic)
{
    size_t ent = entropy.size() * 8;
    if (ent < 128 || ent > 256 || ent % 32 != 0) return false;

    uint8_t hash[32];
    INFRATIC_SHA256_ONESHOT(entropy.data(), entropy.size(), hash, 0);
    size_t cs = ent / 32;
    std::vector<uint8_t> bits(entropy);
    bits.push_back(hash[0]);

    outMnemonic = "";
    size_t words = (ent + cs) / 11;
    for (size_t w = 0; w < words; w++)
    {
        int idx = 0;
        for (int b = 0; b < 11; b++)
        {
            size_t bit = w * 11 + b;
            idx = (idx << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1);
        }
        if (w) outMnemonic += " ";
        outMnemonic += wordAt(idx);
    }
    return true;
}

bool Mnemonic::toEntropy(const String &mnemonic, std::vector<uint8_t> &outEntropy)
{
    std::vector<String> words = splitWords(mnemonic);
    size_t n = words.size();
    if (n < 12 || n > 24 || n % 3 != 0) return false;

    size_t totalBits = n * 11;
    size_t cs = totalBits / 33;
    size_t ent = totalBits - cs;
    std::vector<uint8_t> bits((totalBits + 7) / 8, 0);
    for (size_t w = 0; w < n; w++)
    {
        int idx = indexOfWord(words[w]);
        if (idx < 0) return false;
        for (int b = 0; b < 11; b++)
        {
            if ((idx >> (10 - b)) & 1)
            {
                size_t bit = w * 11 + b;
                bits[bit / 8] |= 0x80 >> (bit % 8);
            }
        }
    }

    outEntropy.assign(bits.begin(), bits.begin() + ent / 8);
    uint8_t hash[32];
    INFRATIC_SHA256_ONESHOT(outEntropy.data(), outEntropy.size(), hash, 0);
    uint8_t expected = hash[0] >> (8 - cs);
    uint8_t actual = bits[ent / 8] >> (8 - cs);
    if (expected != actual)
    {
        outEntropy.clear();
        return false;
    }
    return true;
}

bool Mnemonic::isValid(const String &mnemonic)
{
    std::vector<uint8_t> e;
    return toEntropy(mnemonic, e);
}

String Mnemonic::generate(uint8_t words)
{
    size_t bytes = words == 24 ? 32 : words == 18 ? 24 : words == 15 ? 20 : words == 21 ? 28 : 16;
    std::vector<uint8_t> entropy(bytes);
    randomBytes(entropy.data(), bytes);
    String m;
    fromEntropy(entropy, m);
    wipeBytes(entropy.data(), entropy.size());
    return m;
}

bool Mnemonic::toSeed(const String &mnemonic, const String &passphrase, uint8_t outSeed[64])
{
    // normalized as single spaces, lower case (ASCII English wordlist)
    std::vector<String> words = splitWords(mnemonic);
    String norm;
    for (size_t i = 0; i < words.size(); i++)
    {
        if (i) norm += " ";
        norm += words[i];
    }
    String salt = "mnemonic" + passphrase;
    return pbkdf2(MBEDTLS_MD_SHA512, (const uint8_t *)norm.c_str(), norm.length(),
                  (const uint8_t *)salt.c_str(), salt.length(), 2048, outSeed, 64);
}

bool Mnemonic::deriveEd25519(const uint8_t seed[64], const std::vector<uint32_t> &path, uint8_t outKey[32])
{
    uint8_t I[64];
    const char *curve = "ed25519 seed";
    if (!hmacSha512((const uint8_t *)curve, strlen(curve), seed, 64, I)) return false;

    for (uint32_t index : path)
    {
        uint32_t hardened = index | 0x80000000u;
        uint8_t data[37];
        data[0] = 0;
        memcpy(data + 1, I, 32);
        data[33] = hardened >> 24;
        data[34] = hardened >> 16;
        data[35] = hardened >> 8;
        data[36] = hardened;
        uint8_t chain[32];
        memcpy(chain, I + 32, 32);
        bool ok = hmacSha512(chain, 32, data, sizeof(data), I);
        wipeBytes(data, sizeof(data));
        wipeBytes(chain, sizeof(chain));
        if (!ok) return false;
    }
    memcpy(outKey, I, 32);
    wipeBytes(I, sizeof(I));
    return true;
}

Keypair Keypair::fromMnemonic(const String &mnemonic, uint32_t account, const String &passphrase)
{
    if (!Mnemonic::isValid(mnemonic))
    {
        _logErr.println("❌ Invalid mnemonic");
        return Keypair();
    }
    uint8_t seed[64], key[32];
    Keypair kp;
    if (Mnemonic::toSeed(mnemonic, passphrase, seed) &&
        Mnemonic::deriveEd25519(seed, {44, 501, account, 0}, key))
    {
        kp = Keypair::fromSeed(key);
    }
    wipeBytes(seed, sizeof(seed));
    wipeBytes(key, sizeof(key));
    return kp;
}

// ----------------------------------------------------------------------------
// KeyStore
// blob: version | type | iterations(u32 LE) | salt[16] | iv[12] | tag[16] | ciphertext
// ----------------------------------------------------------------------------

KeyStore::KeyStore(const String &name) : _name(name.substring(0, 12)) {}

bool KeyStore::exists()
{
    Preferences prefs;
    if (!prefs.begin(KS_NAMESPACE, true)) return false;
    bool ok = prefs.getBytesLength(_name.c_str()) > 0;
    prefs.end();
    return ok;
}

uint8_t KeyStore::failedAttempts()
{
    Preferences prefs;
    if (!prefs.begin(KS_NAMESPACE, true)) return 0;
    uint8_t n = prefs.getUChar((_name + "_f").c_str(), 0);
    prefs.end();
    return n;
}

bool KeyStore::wipe()
{
    Preferences prefs;
    if (!prefs.begin(KS_NAMESPACE, false)) return false;
    prefs.remove(_name.c_str());
    prefs.remove((_name + "_f").c_str());
    prefs.end();
    _logInfo.println("🧹 Key store wiped: " + _name);
    return true;
}

bool KeyStore::save(uint8_t type, const std::vector<uint8_t> &secret, const String &pin)
{
    if (pin.length() < 4)
    {
        _logErr.println("❌ PIN must be at least 4 characters");
        return false;
    }

    std::vector<uint8_t> blob(2 + 4 + 16 + 12 + 16 + secret.size());
    blob[0] = KS_VERSION;
    blob[1] = type;
    for (int i = 0; i < 4; i++) blob[2 + i] = (uint8_t)(_iterations >> (8 * i));
    uint8_t *salt = blob.data() + 6, *iv = blob.data() + 22, *tag = blob.data() + 34, *ct = blob.data() + 50;
    randomBytes(salt, 16);
    randomBytes(iv, 12);

    uint8_t key[32];
    if (!pbkdf2(MBEDTLS_MD_SHA256, (const uint8_t *)pin.c_str(), pin.length(), salt, 16, _iterations, key, 32))
    {
        return false;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    String aad = "infratic-ks:" + _name;
    bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
              mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, secret.size(), iv, 12,
                                        (const uint8_t *)aad.c_str(), aad.length(), secret.data(), ct, 16, tag) == 0;
    mbedtls_gcm_free(&gcm);
    wipeBytes(key, sizeof(key));
    if (!ok) return false;

    Preferences prefs;
    if (!prefs.begin(KS_NAMESPACE, false)) return false;
    ok = prefs.putBytes(_name.c_str(), blob.data(), blob.size()) == blob.size();
    prefs.putUChar((_name + "_f").c_str(), 0);
    prefs.end();
    _logInfo.println(ok ? "🔐 Key stored: " + _name : "❌ Could not write key store");
    return ok;
}

bool KeyStore::decrypt(const String &pin, uint8_t &outType, std::vector<uint8_t> &outSecret)
{
    Preferences prefs;
    if (!prefs.begin(KS_NAMESPACE, false)) return false;
    size_t len = prefs.getBytesLength(_name.c_str());
    if (len < 51)
    {
        prefs.end();
        _logErr.println("❌ No key stored: " + _name);
        return false;
    }
    std::vector<uint8_t> blob(len);
    prefs.getBytes(_name.c_str(), blob.data(), len);

    uint32_t iterations = 0;
    for (int i = 0; i < 4; i++) iterations |= (uint32_t)blob[2 + i] << (8 * i);
    const uint8_t *salt = blob.data() + 6, *iv = blob.data() + 22, *tag = blob.data() + 34, *ct = blob.data() + 50;
    size_t ctLen = len - 50;

    uint8_t key[32];
    bool ok = blob[0] == KS_VERSION &&
              pbkdf2(MBEDTLS_MD_SHA256, (const uint8_t *)pin.c_str(), pin.length(), salt, 16, iterations, key, 32);

    outSecret.assign(ctLen, 0);
    if (ok)
    {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        String aad = "infratic-ks:" + _name;
        ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
             mbedtls_gcm_auth_decrypt(&gcm, ctLen, iv, 12, (const uint8_t *)aad.c_str(), aad.length(), tag, 16, ct,
                                      outSecret.data()) == 0;
        mbedtls_gcm_free(&gcm);
    }
    wipeBytes(key, sizeof(key));

    String failKey = _name + "_f";
    if (!ok)
    {
        wipeBytes(outSecret.data(), outSecret.size());
        outSecret.clear();
        uint8_t fails = prefs.getUChar(failKey.c_str(), 0) + 1;
        prefs.putUChar(failKey.c_str(), fails);
        _logErr.printf("❌ Wrong PIN (%u/%u)\n", fails, _maxAttempts);
        if (_maxAttempts > 0 && fails >= _maxAttempts)
        {
            prefs.remove(_name.c_str());
            prefs.remove(failKey.c_str());
            _logErr.println("🧹 Too many wrong PINs, key store wiped");
        }
        prefs.end();
        return false;
    }

    prefs.putUChar(failKey.c_str(), 0);
    prefs.end();
    outType = blob[1];
    return true;
}

bool KeyStore::saveMnemonic(const String &mnemonic, const String &pin)
{
    std::vector<uint8_t> entropy;
    if (!Mnemonic::toEntropy(mnemonic, entropy))
    {
        _logErr.println("❌ Invalid mnemonic");
        return false;
    }
    bool ok = save(KS_TYPE_MNEMONIC, entropy, pin);
    wipeBytes(entropy.data(), entropy.size());
    return ok;
}

bool KeyStore::saveSeed(const uint8_t seed[32], const String &pin)
{
    std::vector<uint8_t> s(seed, seed + 32);
    bool ok = save(KS_TYPE_SEED, s, pin);
    wipeBytes(s.data(), s.size());
    return ok;
}

bool KeyStore::unlock(const String &pin, Keypair &outKeypair, uint32_t account, const String &passphrase)
{
    uint8_t type = 0;
    std::vector<uint8_t> secret;
    if (!decrypt(pin, type, secret)) return false;

    bool ok = false;
    if (type == KS_TYPE_SEED && secret.size() == 32)
    {
        outKeypair = Keypair::fromSeed(secret.data());
        ok = true;
    }
    else if (type == KS_TYPE_MNEMONIC)
    {
        String m;
        if (Mnemonic::fromEntropy(secret, m))
        {
            outKeypair = Keypair::fromMnemonic(m, account, passphrase);
            ok = !outKeypair.privkey.empty();
        }
    }
    wipeBytes(secret.data(), secret.size());
    return ok;
}

bool KeyStore::unlockMnemonic(const String &pin, String &outMnemonic)
{
    uint8_t type = 0;
    std::vector<uint8_t> secret;
    if (!decrypt(pin, type, secret)) return false;
    bool ok = type == KS_TYPE_MNEMONIC && Mnemonic::fromEntropy(secret, outMnemonic);
    wipeBytes(secret.data(), secret.size());
    return ok;
}

bool KeyStore::changePin(const String &oldPin, const String &newPin)
{
    uint8_t type = 0;
    std::vector<uint8_t> secret;
    if (!decrypt(oldPin, type, secret)) return false;
    bool ok = save(type, secret, newPin);
    wipeBytes(secret.data(), secret.size());
    return ok;
}
