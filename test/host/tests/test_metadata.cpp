// Token metadata: Metaplex accounts, Token-2022 extensions, PDAs and the unified lookup.
// Vectors: ../js/gen_metadata.mjs (official mpl-token-metadata / spl-token / spl-token-metadata).
namespace infratic_detail { String toBase64(const uint8_t *data, size_t len); }

static std::string metaAccountJson(const std::vector<uint8_t> &data, const std::string &owner)
{
    String b64 = infratic_detail::toBase64(data.data(), data.size());
    return std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":{\"data\":[\"") +
           b64.c_str() + "\",\"base64\"],\"executable\":false,\"lamports\":1,\"owner\":\"" + owner + "\",\"space\":" +
           std::to_string(data.size()) + "}}}";
}

INFRATIC_TEST(metadata)
{
    const std::string kMeta = vec["programs"]["metaplex"].as<std::string>();
    const std::string kToken = vec["programs"]["token"].as<std::string>();
    const std::string kToken22 = vec["programs"]["token2022"].as<std::string>();

    // ---- Metaplex parsing + PDAs -------------------------------------------------
    for (JsonObject c : vec["metaplex"].as<JsonArray>())
    {
        std::string n = c["name"].as<std::string>();
        std::vector<uint8_t> data = fromHex(c["data"].as<std::string>());
        JsonObject e = c["expect"];
        MetaplexMetadata m;
        CHECK(TokenMetadataParser::parseMetaplex(data, m), n + " parses");
        CHECK(m.key == 4, n + " key");
        CHECK(m.updateAuthority == e["updateAuthority"].as<const char *>(), n + " update authority");
        CHECK(m.mint == c["mint"].as<const char *>(), n + " mint");
        CHECK(m.name == e["name"].as<const char *>() && m.symbol == e["symbol"].as<const char *>() &&
                  m.uri == e["uri"].as<const char *>(), n + " name/symbol/uri without padding");
        CHECK(m.sellerFeeBasisPoints == e["fee"].as<int>(), n + " seller fee");
        CHECK(m.primarySaleHappened == e["primary"].as<bool>() && m.isMutable == e["isMutable"].as<bool>(), n + " flags");

        JsonVariant creators = e["creators"];
        CHECK(m.hasCreators == !creators.isNull(), n + " creators presence");
        if (!creators.isNull() && m.hasCreators)
        {
            JsonArray a = creators.as<JsonArray>();
            bool same = a.size() == m.creators.size();
            for (size_t i = 0; same && i < a.size(); i++)
                same = m.creators[i].address == a[i]["address"].as<const char *>() &&
                       m.creators[i].verified == a[i]["verified"].as<bool>() && m.creators[i].share == a[i]["share"].as<int>();
            CHECK(same, n + " creators");
        }
        CHECK(m.hasEditionNonce == !e["nonce"].isNull() && (!m.hasEditionNonce || m.editionNonce == e["nonce"].as<int>()), n + " edition nonce");
        CHECK(m.hasTokenStandard == !e["standard"].isNull() && (!m.hasTokenStandard || m.tokenStandard == e["standard"].as<int>()), n + " token standard");
        CHECK(m.hasCollection == !e["collection"].isNull() &&
                  (!m.hasCollection || (m.collectionKey == e["collection"]["key"].as<const char *>() &&
                                        m.collectionVerified == e["collection"]["verified"].as<bool>())), n + " collection");
        CHECK(m.hasUses == !e["uses"].isNull() &&
                  (!m.hasUses || (m.useMethod == e["uses"]["useMethod"].as<int>() &&
                                  std::to_string(m.usesRemaining) == e["uses"]["remaining"].as<std::string>() &&
                                  std::to_string(m.usesTotal) == e["uses"]["total"].as<std::string>())), n + " uses");

        String pda, ed;
        CHECK(sol.getMetadataPda(c["mint"].as<const char *>(), pda) && pda == c["metadataPda"].as<const char *>(), n + " metadata PDA");
        CHECK(sol.getMasterEditionPda(c["mint"].as<const char *>(), ed) && ed == c["masterEditionPda"].as<const char *>(), n + " master edition PDA");

        // truncation: never crashes, fails below the mandatory part, keeps the strings above it
        size_t minLen = c["minLen"].as<size_t>();
        bool ok = true;
        for (size_t len = 0; len < data.size(); len++)
        {
            std::vector<uint8_t> cut(data.begin(), data.begin() + len);
            MetaplexMetadata t;
            bool r = TokenMetadataParser::parseMetaplex(cut, t);
            if (len < minLen) ok = ok && !r;
            else ok = ok && r && t.name == m.name && t.uri == m.uri && t.mint == m.mint;
        }
        CHECK(ok, n + " truncated prefixes");
    }
    {
        MetaplexMetadata m;
        std::vector<uint8_t> d = fromHex(vec["metaplex"][1]["data"].as<std::string>());
        d[0] = 1; // not a MetadataV1 account
        CHECK(!TokenMetadataParser::parseMetaplex(d, m), "wrong account key rejected");
        CHECK(!TokenMetadataParser::parseMetaplex(std::vector<uint8_t>(), m), "empty data rejected");
        d = fromHex(vec["metaplex"][0]["data"].as<std::string>());
        d[65] = 0xff; d[66] = 0xff; d[67] = 0xff; d[68] = 0xff; // name length beyond the data
        CHECK(!TokenMetadataParser::parseMetaplex(d, m), "oversized name length rejected");
        d = fromHex(vec["metaplex"][1]["data"].as<std::string>());
        size_t cOff = 1 + 64 + 4 + 32 + 4 + 10 + 4 + 200 + 2; // creators option tag
        d[cOff + 1] = 0xff; d[cOff + 2] = 0xff; d[cOff + 3] = 0xff; d[cOff + 4] = 0x7f; // huge creators count
        CHECK(TokenMetadataParser::parseMetaplex(d, m) && !m.hasCreators && m.name == "Cool Cat #42", "huge creators count tolerated");
    }

    // ---- Token-2022 parsing ------------------------------------------------------
    for (JsonObject c : vec["token2022"].as<JsonArray>())
    {
        std::string n = std::string("t22 ") + c["name"].as<const char *>();
        std::vector<uint8_t> data = fromHex(c["data"].as<std::string>());
        Token2022Metadata t;
        CHECK(TokenMetadataParser::parseToken2022(data, t), n + " parses");
        CHECK(t.decimals == c["decimals"].as<int>(), n + " decimals");
        CHECK(t.hasMetadataPointer == c["hasPointer"].as<bool>(), n + " pointer presence");
        if (t.hasMetadataPointer)
            CHECK(t.pointerAuthority == c["pointerAuthority"].as<const char *>() && t.pointerAddress == c["pointerAddress"].as<const char *>(), n + " pointer fields");
        CHECK(t.hasTokenMetadata == c["hasMeta"].as<bool>(), n + " metadata presence");
        if (t.hasTokenMetadata)
        {
            CHECK(t.updateAuthority == c["updateAuthority"].as<const char *>() && t.mint == c["mint"].as<const char *>(), n + " authority/mint");
            CHECK(t.name == c["metaName"].as<const char *>() && t.symbol == c["symbol"].as<const char *>() && t.uri == c["uri"].as<const char *>(), n + " name/symbol/uri");
            JsonArray add = c["additional"].as<JsonArray>();
            bool same = add.size() == t.additional.size();
            for (size_t i = 0; same && i < add.size(); i++)
                same = t.additional[i].key == add[i]["key"].as<const char *>() && t.additional[i].value == add[i]["value"].as<const char *>();
            CHECK(same, n + " additional metadata");
        }
        bool ok = true; // truncated mints must not crash and never report garbage
        for (size_t len = 0; len < data.size(); len++)
        {
            Token2022Metadata x;
            std::vector<uint8_t> cut(data.begin(), data.begin() + len);
            bool r = TokenMetadataParser::parseToken2022(cut, x);
            if (len <= 166) ok = ok && !r;
            if (x.hasTokenMetadata) ok = ok && x.name == t.name && x.uri == t.uri;
        }
        CHECK(ok, n + " truncated prefixes");
    }
    {
        Token2022Metadata t;
        std::vector<uint8_t> d = fromHex(vec["token2022"][0]["data"].as<std::string>());
        d[165] = 2; // account type = token account, not a mint
        CHECK(!TokenMetadataParser::parseToken2022(d, t), "wrong account type rejected");
        CHECK(!TokenMetadataParser::parseToken2022(fromHex(vec["plainMint"]["data"].as<std::string>()), t), "plain mint has no extensions");
    }

    // ---- getTokenMetadata with a mocked RPC ---------------------------------------
    std::map<std::string, std::pair<std::string, std::vector<uint8_t>>> accounts; // address -> (owner, data)
    g_httpHandler = [&](const std::string &, const std::string &body) -> MockHttpResponse {
        DynamicJsonDocument d(2048);
        deserializeJson(d, body);
        std::string addr = d["params"][0].as<std::string>();
        auto it = accounts.find(addr);
        if (it == accounts.end())
            return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":1},\"value\":null}}"};
        return {200, metaAccountJson(it->second.second, it->second.first)};
    };

    JsonArray mp = vec["metaplex"].as<JsonArray>();
    std::vector<uint8_t> plain = fromHex(vec["plainMint"]["data"].as<std::string>());
    {
        JsonObject c = mp[0]; // fungible with padded metadata
        std::string mint = c["mint"].as<std::string>();
        accounts.clear();
        accounts[mint] = {kToken, plain};
        accounts[c["metadataPda"].as<std::string>()] = {kMeta, fromHex(c["data"].as<std::string>())};
        TokenMetadata tm;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && tm.found && tm.source == "metaplex", "metaplex lookup");
        CHECK(tm.name == "USD Coin" && tm.symbol == "USDC" && tm.uri == "https://example.com/usdc.json", "metaplex strings");
        CHECK(tm.decimals == vec["plainMint"]["decimals"].as<int>() && tm.isMutable == c["expect"]["isMutable"].as<bool>() &&
                  tm.updateAuthority == c["expect"]["updateAuthority"].as<const char *>(), "metaplex decimals/authority/mutable");

        // wrong owner of the metadata account: treated as no metadata
        accounts[c["metadataPda"].as<std::string>()].first = kToken;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && !tm.found, "metadata account with wrong owner ignored");
        accounts[c["metadataPda"].as<std::string>()].first = kMeta;

        // metadata of a different mint is not accepted
        accounts[c["metadataPda"].as<std::string>()].second = fromHex(mp[1]["data"].as<std::string>());
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && !tm.found, "metadata for another mint ignored");

        // truncated metadata account
        std::vector<uint8_t> d = fromHex(c["data"].as<std::string>());
        d.resize(40);
        accounts[c["metadataPda"].as<std::string>()].second = d;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && !tm.found, "truncated metadata account ignored");

        // no metadata account at all
        accounts.erase(c["metadataPda"].as<std::string>());
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && !tm.found && tm.source.isEmpty(), "mint without metadata");

        // missing mint / wrong owner of the mint
        accounts.erase(mint);
        CHECK(!sol.getTokenMetadata(mint.c_str(), tm) && !tm.found, "missing mint fails");
        accounts[mint] = {"11111111111111111111111111111111", plain};
        CHECK(!sol.getTokenMetadata(mint.c_str(), tm) && !tm.found, "mint owned by the wrong program fails");
        CHECK(!sol.getTokenMetadata("not-an-address", tm), "invalid mint string");
    }
    {
        JsonObject c = mp[1]; // immutable NFT, 0 decimals not needed, uses plain mint
        accounts.clear();
        std::string mint = c["mint"].as<std::string>();
        accounts[mint] = {kToken, plain};
        accounts[c["metadataPda"].as<std::string>()] = {kMeta, fromHex(c["data"].as<std::string>())};
        TokenMetadata tm;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && tm.found && tm.name == "Cool Cat #42" && tm.isMutable == false, "metaplex immutable");
    }

    JsonArray t22 = vec["token2022"].as<JsonArray>();
    {
        JsonObject c = t22[0]; // pointer + metadata, mutable
        std::string mint = c["mint"].as<std::string>();
        accounts.clear();
        accounts[mint] = {kToken22, fromHex(c["data"].as<std::string>())};
        // a Metaplex account exists too, but the extension wins
        accounts[c["metadataPda"].as<std::string>()] = {kMeta, fromHex(mp[0]["data"].as<std::string>())};
        TokenMetadata tm;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && tm.found && tm.source == "token-2022", "token-2022 source");
        CHECK(tm.name == "Pyth USD" && tm.symbol == "PUSD" && tm.uri == "https://example.com/pusd.json" && tm.decimals == 9, "token-2022 fields");
        CHECK(tm.isMutable && tm.updateAuthority == c["updateAuthority"].as<const char *>(), "token-2022 mutable");

        // same mint data owned by the classic Token program: extensions are not used
        accounts[mint].first = kToken;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && !tm.found, "extension ignored when owner is Token program");
    }
    {
        JsonObject c = t22[1]; // immutable
        std::string mint = c["mint"].as<std::string>();
        accounts.clear();
        accounts[mint] = {kToken22, fromHex(c["data"].as<std::string>())};
        TokenMetadata tm;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && tm.found && !tm.isMutable && tm.updateAuthority.isEmpty() && tm.decimals == 6, "token-2022 immutable");
    }
    {
        JsonObject c = t22[5]; // Token-2022 mint without metadata: falls back to Metaplex PDA
        std::string mint = c["mint"].as<std::string>();
        accounts.clear();
        accounts[mint] = {kToken22, fromHex(c["data"].as<std::string>())};
        TokenMetadata tm;
        CHECK(sol.getTokenMetadata(mint.c_str(), tm) && !tm.found, "token-2022 without metadata and without PDA");
        // 82-byte token-2022 mint (no extension) with a Metaplex account
        JsonObject m = mp[3];
        accounts.clear();
        accounts[m["mint"].as<std::string>()] = {kToken22, plain};
        accounts[m["metadataPda"].as<std::string>()] = {kMeta, fromHex(m["data"].as<std::string>())};
        CHECK(sol.getTokenMetadata(m["mint"].as<const char *>(), tm) && tm.found && tm.source == "metaplex" && tm.name == "Tight", "token-2022 mint falls back to metaplex");
    }
    {
        // RPC error object
        g_httpHandler = [&](const std::string &, const std::string &) -> MockHttpResponse {
            return {200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid param\"}}"};
        };
        TokenMetadata tm;
        CHECK(!sol.getTokenMetadata(mp[0]["mint"].as<const char *>(), tm) && !tm.found, "RPC error");
    }
}
