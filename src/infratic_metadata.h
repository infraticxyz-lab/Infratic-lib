// Token metadata: Metaplex Token Metadata accounts and the Token-2022 metadata extension.
#ifndef INFRATIC_METADATA_H
#define INFRATIC_METADATA_H

#include <Arduino.h>
#include <vector>

#define INFRATIC_METAPLEX_METADATA_PROGRAM_ID "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"

/** One entry of the Metaplex creators list */
struct MetaplexCreator
{
    String address;
    bool verified;
    uint8_t share; // percent, all shares add up to 100

    MetaplexCreator() : verified(false), share(0) {}
};

/** A parsed Metaplex Token Metadata account (strings have their NUL padding removed) */
struct MetaplexMetadata
{
    uint8_t key;               // account discriminator, 4 = MetadataV1
    String updateAuthority;    // base58
    String mint;               // base58
    String name;
    String symbol;
    String uri;
    uint16_t sellerFeeBasisPoints;
    bool hasCreators;
    std::vector<MetaplexCreator> creators;
    bool primarySaleHappened;
    bool isMutable;
    bool hasEditionNonce;
    uint8_t editionNonce;
    bool hasTokenStandard;
    uint8_t tokenStandard;     // 0 NonFungible, 1 FungibleAsset, 2 Fungible, 3 NonFungibleEdition, 4 Programmable...
    bool hasCollection;
    bool collectionVerified;
    String collectionKey;      // base58
    bool hasUses;
    uint8_t useMethod;         // 0 Burn, 1 Multiple, 2 Single
    uint64_t usesRemaining;
    uint64_t usesTotal;

    MetaplexMetadata()
        : key(0), sellerFeeBasisPoints(0), hasCreators(false), primarySaleHappened(false), isMutable(false),
          hasEditionNonce(false), editionNonce(0), hasTokenStandard(false), tokenStandard(0), hasCollection(false),
          collectionVerified(false), hasUses(false), useMethod(0), usesRemaining(0), usesTotal(0) {}
};

/** A key/value pair of the Token-2022 additional_metadata list */
struct MetadataField
{
    String key;
    String value;
};

/** Metadata found in the extensions of a Token-2022 mint account */
struct Token2022Metadata
{
    uint8_t decimals;
    bool hasMetadataPointer;      // MetadataPointer extension (type 18) present
    String pointerAuthority;      // base58, empty if none
    String pointerAddress;        // account that holds the metadata, empty if none
    bool hasTokenMetadata;        // TokenMetadata extension (type 19) present
    String updateAuthority;       // base58, empty if the metadata is immutable
    String mint;                  // base58
    String name;
    String symbol;
    String uri;
    std::vector<MetadataField> additional;

    Token2022Metadata() : decimals(0), hasMetadataPointer(false), hasTokenMetadata(false) {}
};

/** Result of Infratic::getTokenMetadata() */
struct TokenMetadata
{
    bool found;
    String source;           // "token-2022" or "metaplex"
    String name;
    String symbol;
    String uri;
    uint8_t decimals;
    String updateAuthority;  // base58, empty if none
    bool isMutable;

    TokenMetadata() : found(false), decimals(0), isMutable(false) {}
};

/** Offline parsers for token metadata account data. They never read out of bounds. */
class TokenMetadataParser
{
public:
    /**
     * @brief Parses a Metaplex Metadata account. Unknown trailing data is ignored and
     *        accounts that end early (old layouts) keep the defaults for the missing fields.
     * @return false if the data is too short to hold name, symbol, uri and the fee, or is not a MetadataV1 account
     */
    static bool parseMetaplex(const std::vector<uint8_t> &data, MetaplexMetadata &out);

    /**
     * @brief Parses the TLV extensions of a Token-2022 mint account and fills decimals,
     *        MetadataPointer and TokenMetadata when present.
     * @return false if the data is not a Token-2022 mint with extensions
     */
    static bool parseToken2022(const std::vector<uint8_t> &mintData, Token2022Metadata &out);

    /** @brief Removes trailing NUL bytes (Metaplex pads name/symbol/uri) */
    static String stripNul(const String &s);
};

#endif // INFRATIC_METADATA_H
