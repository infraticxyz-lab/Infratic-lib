// Reference vectors for token metadata, built with the official Metaplex and SPL libraries.
// Run: node gen_metadata.mjs   (writes ../vectors_metadata.json, deterministic)
import { writeFileSync } from 'node:fs';
import { PublicKey } from '@solana/web3.js';
import { MintLayout, ExtensionType, AccountType, MetadataPointerLayout, TYPE_SIZE, LENGTH_SIZE,
  TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, ACCOUNT_SIZE } from '@solana/spl-token';
import { pack } from '@solana/spl-token-metadata';
import { publicKey, some, none } from '@metaplex-foundation/umi';
import { getMetadataAccountDataSerializer, findMetadataPda, findMasterEditionPda, Key, TokenStandard, UseMethod,
  MPL_TOKEN_METADATA_PROGRAM_ID } from '@metaplex-foundation/mpl-token-metadata';

// deterministic PRNG so the vectors are stable
let s = 0x2545f491;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const hex = (b) => Buffer.from(b).toString('hex');
const key = () => new PublicKey(bytes(32));

// Minimal umi context: the official findMetadataPda/findMasterEditionPda build the seeds,
// web3.js does the program address search.
const umi = {
  programs: { getPublicKey: (_name, fallback) => fallback },
  eddsa: { findPda: (program, seeds) => {
    const [pk, bump] = PublicKey.findProgramAddressSync(seeds.map((x) => Buffer.from(x)), new PublicKey(program));
    return [pk.toBase58(), bump];
  } },
};
const ser = getMetadataAccountDataSerializer();
const pad = (str, n) => str + '\0'.repeat(n - str.length); // on-chain padding

function metaplexCase(name, f) {
  const mint = key();
  const update = key();
  const m = {
    key: Key.MetadataV1, updateAuthority: publicKey(update.toBase58()), mint: publicKey(mint.toBase58()),
    name: pad(f.name, f.padded === false ? f.name.length : 32),
    symbol: pad(f.symbol, f.padded === false ? f.symbol.length : 10),
    uri: pad(f.uri, f.padded === false ? f.uri.length : 200),
    sellerFeeBasisPoints: f.fee ?? 0,
    creators: f.creators ? some(f.creators.map((c) => ({ address: publicKey(c.address), verified: c.verified, share: c.share }))) : none(),
    primarySaleHappened: f.primary ?? false, isMutable: f.mutable ?? true,
    editionNonce: f.nonce === undefined ? none() : some(f.nonce),
    tokenStandard: f.standard === undefined ? none() : some(f.standard),
    collection: f.collection ? some({ verified: f.collection.verified, key: publicKey(f.collection.key) }) : none(),
    uses: f.uses ? some(f.uses) : none(),
    collectionDetails: none(), programmableConfig: none(),
  };
  const data = Buffer.from(ser.serialize(m));
  const mintPk = publicKey(mint.toBase58());
  const pda = findMetadataPda(umi, { mint: mintPk })[0];
  const edition = findMasterEditionPda(umi, { mint: mintPk })[0];
  // length after the fields that are mandatory for the parser: key + 2 pubkeys + 3 strings + fee
  const minLen = 1 + 64 + 3 * 4 + Buffer.byteLength(m.name) + Buffer.byteLength(m.symbol) + Buffer.byteLength(m.uri) + 2;
  return {
    name, mint: mint.toBase58(), data: hex(data), minLen, metadataPda: pda, masterEditionPda: edition,
    expect: {
      key: 4, updateAuthority: update.toBase58(), name: f.name, symbol: f.symbol, uri: f.uri,
      fee: m.sellerFeeBasisPoints, creators: f.creators ?? null, primary: m.primarySaleHappened, isMutable: m.isMutable,
      nonce: f.nonce ?? null, standard: f.standard ?? null, collection: f.collection ?? null,
      uses: f.uses ? { useMethod: f.uses.useMethod, remaining: String(f.uses.remaining), total: String(f.uses.total) } : null,
    },
  };
}

const creator = (verified, share) => ({ address: key().toBase58(), verified, share });
const metaplex = [
  metaplexCase('usdc-like fungible', { name: 'USD Coin', symbol: 'USDC', uri: 'https://example.com/usdc.json', standard: TokenStandard.Fungible, nonce: undefined }),
  metaplexCase('nft with everything', {
    name: 'Cool Cat #42', symbol: 'CAT', uri: 'https://arweave.net/abcDEF123_-xyz', fee: 550,
    creators: [creator(true, 60), creator(false, 40)], primary: true, mutable: false, nonce: 253,
    standard: TokenStandard.NonFungible, collection: { verified: true, key: key().toBase58() },
    uses: { useMethod: UseMethod.Multiple, remaining: 7n, total: 10n },
  }),
  metaplexCase('immutable five creators', {
    name: 'Max', symbol: 'M', uri: 'ipfs://bafy', fee: 10000,
    creators: [1, 2, 3, 4, 5].map((i) => creator(i % 2 === 0, 20)), mutable: false, standard: TokenStandard.ProgrammableNonFungible,
  }),
  metaplexCase('unpadded strings', { name: 'Tight', symbol: 'TGT', uri: 'u', padded: false }),
  metaplexCase('empty strings', { name: '', symbol: '', uri: '' }),
  metaplexCase('utf8 name', { name: 'Café €', symbol: 'CFE', uri: 'https://x.y/é.json', nonce: 0, collection: { verified: false, key: key().toBase58() } }),
  metaplexCase('full width fields', { name: 'N'.repeat(32), symbol: 'S'.repeat(10), uri: 'u'.repeat(200) }),
];
// old accounts: the layout simply ends after is_mutable (and creators)
{
  const base = metaplex[0];
  const d = Buffer.from(base.data, 'hex');
  // key + authority + mint + three padded strings + fee = minLen; then creators none, primary, mutable
  const cut = base.minLen + 1 + 2;
  metaplex.push({ ...base, name: 'old account ends after is_mutable', data: hex(d.subarray(0, cut)),
    expect: { ...base.expect, standard: null, nonce: null } });
  const withTrailing = Buffer.concat([d, Buffer.from(bytes(64))]);
  metaplex.push({ ...base, name: 'unknown trailing data', data: hex(withTrailing) });
}

// ---- Token-2022 ----------------------------------------------------------------
const u16le = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const tlv = (type, value) => Buffer.concat([u16le(type), u16le(value.length), value]);

function mintBase(decimals) {
  const b = Buffer.alloc(ACCOUNT_SIZE); // 165 bytes
  MintLayout.encode({ mintAuthorityOption: 1, mintAuthority: key(), supply: BigInt(1000000 + rnd() % 1000), decimals,
    isInitialized: true, freezeAuthorityOption: 0, freezeAuthority: PublicKey.default }, b);
  return Buffer.concat([b, Buffer.from([AccountType.Mint])]);
}

function t22Case(name, f) {
  const mint = key();
  const update = f.immutable ? undefined : key();
  const pointerAuth = f.pointerAuthority === null ? PublicKey.default : key();
  const parts = [mintBase(f.decimals)];
  const exts = [];
  if (f.padExt) exts.push(tlv(ExtensionType.TransferFeeConfig, Buffer.from(bytes(108)))); // unrelated extension first
  let pointerAddr = null;
  if (f.pointer) {
    pointerAddr = f.pointerSelf ? mint : key();
    const pl = Buffer.alloc(MetadataPointerLayout.span);
    MetadataPointerLayout.encode({ authority: pointerAuth, metadataAddress: pointerAddr }, pl);
    exts.push(tlv(ExtensionType.MetadataPointer, pl));
  }
  let metaBytes = null;
  if (f.meta) {
    metaBytes = Buffer.from(pack({ mint, name: f.meta.name, symbol: f.meta.symbol, uri: f.meta.uri,
      updateAuthority: update, additionalMetadata: f.meta.additional ?? [] }));
    exts.push(tlv(ExtensionType.TokenMetadata, metaBytes));
  }
  const data = Buffer.concat([...parts, ...exts]);
  return {
    name, mint: mint.toBase58(), data: hex(data), decimals: f.decimals,
    hasPointer: !!f.pointer, pointerAuthority: f.pointer && f.pointerAuthority !== null ? pointerAuth.toBase58() : '',
    pointerAddress: pointerAddr ? pointerAddr.toBase58() : '',
    hasMeta: !!f.meta, updateAuthority: update ? update.toBase58() : '',
    metaName: f.meta?.name ?? '', symbol: f.meta?.symbol ?? '', uri: f.meta?.uri ?? '',
    additional: (f.meta?.additional ?? []).map(([k, v]) => ({ key: k, value: v })),
    metadataPda: findMetadataPda(umi, { mint: publicKey(mint.toBase58()) })[0],
  };
}
const token2022 = [
  t22Case('pointer + metadata', { decimals: 9, pointer: true, pointerSelf: true,
    meta: { name: 'Pyth USD', symbol: 'PUSD', uri: 'https://example.com/pusd.json', additional: [['team', 'infratic'], ['site', 'https://i.o']] } }),
  t22Case('metadata only, immutable', { decimals: 6, immutable: true, meta: { name: 'Frozen', symbol: 'FRZ', uri: 'ipfs://x' } }),
  t22Case('unrelated extension first', { decimals: 0, padExt: true, pointer: true, pointerSelf: true, meta: { name: 'Über', symbol: 'UBR', uri: '', additional: [['k', '']] } }),
  t22Case('pointer to other account, no metadata', { decimals: 2, pointer: true, pointerSelf: false }),
  t22Case('pointer without authority', { decimals: 4, pointer: true, pointerAuthority: null, pointerSelf: true, meta: { name: 'NoAuth', symbol: 'NA', uri: 'u' } }),
  t22Case('no metadata extension', { decimals: 3, padExt: true }),
];
// plain SPL mint without extensions (82 bytes) for the owner-mismatch / fallback tests
const plainMint = (decimals) => {
  const b = Buffer.alloc(MintLayout.span);
  MintLayout.encode({ mintAuthorityOption: 1, mintAuthority: key(), supply: 5000000000n, decimals,
    isInitialized: true, freezeAuthorityOption: 0, freezeAuthority: PublicKey.default }, b);
  return hex(b);
};

const out = {
  programs: { metaplex: MPL_TOKEN_METADATA_PROGRAM_ID, token: TOKEN_PROGRAM_ID.toBase58(), token2022: TOKEN_2022_PROGRAM_ID.toBase58() },
  extLayout: { typeSize: TYPE_SIZE, lengthSize: LENGTH_SIZE, accountTypeOffset: ACCOUNT_SIZE },
  metaplex, token2022,
  plainMint: { data: plainMint(6), decimals: 6 },
};
writeFileSync(new URL('../vectors_metadata.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
