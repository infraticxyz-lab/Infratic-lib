// Reference vectors for the commitment / Merkle / attestation / Anchor storage helpers.
// Run: node gen_zk.mjs   (writes ../vectors_zk.json, deterministic)
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { Keypair, PublicKey, Transaction, TransactionInstruction, SystemProgram } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { BorshInstructionCoder } from '@coral-xyz/anchor';

let s = 0x2545f491;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const hex = (b) => Buffer.from(b).toString('hex');
const sha = (...parts) => { const h = createHash('sha256'); parts.forEach((p) => h.update(p)); return h.digest(); };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt.asUintN(64, BigInt(n))); return b; };
const lp = (b) => Buffer.concat([u32le(b.length), Buffer.from(b)]);
const T = (x) => Buffer.from(x);

const out = {};

// ---- commitments: sha256(tag || u32le(len) || data || secret) ----
const commit = (data, secret) => sha(T('infratic-zk/commit/v1'), u32le(data.length), data, secret);
out.commit = [];
const datas = [Buffer.alloc(0), T('temp:25.7C'), Buffer.from([0, 1, 2, 0, 255]), T('a'.repeat(300)), T('ü€')];
for (const d of datas) {
  const secret = Buffer.from(bytes(32));
  out.commit.push({ data: hex(d), secret: hex(secret), commitment: hex(commit(d, secret)) });
}
{
  // legacy createDataCommitment layout: message = lp(data) || lp(secretText) || u64le(ts)
  const data = T('legacy-data'), secretText = 'device-serial-42', ts = 123456;
  const nonce = Buffer.from(bytes(32));
  const msg = Buffer.concat([lp(data), lp(T(secretText)), u64le(ts)]);
  out.legacyCommit = { data: data.toString(), secretText, ts, nonce: hex(nonce), commitment: hex(commit(msg, nonce)) };
}

// ---- Merkle (RFC 6962): leaf = H(0x00||d), node = H(0x01||l||r) ----
const leafH = (d) => sha(Buffer.from([0]), d);
const nodeH = (l, r) => sha(Buffer.from([1]), l, r);
// bottom-up with "promote the unpaired node", an independent formulation of the RFC 6962 tree
function build(leaves) {
  let level = leaves.map(leafH);
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? nodeH(level[i], level[i + 1]) : level[i]);
    level = next; levels.push(level);
  }
  return levels;
}
function proof(levels, index) {
  const sib = [];
  let i = index;
  for (let l = 0; l < levels.length - 1; l++) {
    const j = i ^ 1;
    if (j < levels[l].length) sib.push(levels[l][j]);
    i >>= 1;
  }
  return sib;
}
out.merkle = { sets: [] };
// RFC 6962 / certificate-transparency-go test tree (8 leaves)
const rfcLeaves = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map((h) => Buffer.from(h, 'hex'));
const rfcRoot = hex(build(rfcLeaves).at(-1)[0]);
if (rfcRoot !== '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328') throw new Error('RFC 6962 vector mismatch ' + rfcRoot);
out.merkle.rfc = { leaves: rfcLeaves.map(hex), root: rfcRoot };
out.merkle.emptyLeafHash = hex(leafH(Buffer.alloc(0)));
for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33, 100]) {
  const leaves = Array.from({ length: n }, (_, i) => `item-${i}-${(rnd() % 1000)}`);
  const levels = build(leaves.map(T));
  out.merkle.sets.push({
    leaves, root: hex(levels.at(-1)[0]),
    proofs: leaves.map((_, i) => proof(levels, i).map(hex)),
  });
}

// ---- Ed25519 attestations (deterministic signatures, tweetnacl) ----
const dev = Keypair.fromSeed(bytes(32));
const other = Keypair.fromSeed(bytes(32));
const sign = (msg) => hex(nacl.sign.detached(msg, dev.secretKey));
out.key = { secret: bs58.encode(dev.secretKey), pub: dev.publicKey.toBase58(), otherPub: other.publicKey.toBase58() };
{
  const c = Buffer.from(bytes(32)), ctx = 'temp-sensor/v1', pd = Buffer.from(bytes(9));
  const msg = Buffer.concat([T('infratic-zk/attest/v1'), lp(T(ctx)), c, lp(pd)]);
  out.attest = { commitment: hex(c), context: ctx, publicData: hex(pd), signature: sign(msg) };
  const msg2 = Buffer.concat([T('infratic-zk/attest/v1'), lp(T('')), c, lp(Buffer.alloc(0))]);
  out.attestEmpty = { commitment: hex(c), signature: sign(msg2) };
}
{
  const data = T('{"t":23.4,"h":51}'), t = 1767225600n, bh = hex(bytes(8));
  const blockhash = bs58.encode(bytes(32));
  const mk = (b) => Buffer.concat([T('infratic-zk/timestamp/v1'), sha(data), u64le(t), lp(T(b))]);
  out.timestamp = { data: data.toString(), hash: hex(sha(data)), time: Number(t), blockhash, signature: sign(mk(blockhash)), signatureNoBlockhash: sign(mk('')) };
  const legacy = (d, ts, b) => hex(sha(T('infratic-zk/legacy-timestamp/v1'), u32le(d.length), T(d), u64le(ts), u32le(b.length), T(b)));
  out.legacyTime = { data: 'old-data', ts: Number(t), blockhash, proof: legacy('old-data', t, blockhash) };
}
{
  const value = -17n, lo = -40n, hi = 85n;
  const secret = Buffer.from(bytes(32));
  const c = commit(u64le(value), secret);
  const msg = Buffer.concat([T('infratic-zk/range/v1'), c, u64le(lo), u64le(hi)]);
  out.range = { value: Number(value), min: Number(lo), max: Number(hi), secret: hex(secret), commitment: hex(c), signature: sign(msg) };
}

// ---- Memo + Anchor instruction encoding ----
const MEMO = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const PROGRAM = new PublicKey(bytes(32));
const blockhash = bs58.encode(bytes(32));
const disc = (name) => sha(T('global:' + name)).subarray(0, 8);
const idl = {
  address: PROGRAM.toBase58(),
  metadata: { name: 'zk_storage', version: '0.1.0', spec: '0.1.0' },
  instructions: [
    ['initialize_storage', [['seed_name', 'string']]],
    ['store_commitment', [['commitment', { array: ['u8', 32] }], ['metadata', 'string'], ['timestamp', 'u64']]],
    ['update_commitment', [['new_commitment', { array: ['u8', 32] }], ['metadata', 'string'], ['timestamp', 'u64']]],
    ['store_merkle_root', [['merkle_root', { array: ['u8', 32] }], ['leaf_count', 'u32'], ['metadata', 'string']]],
    ['store_batch', [['batch_root', { array: ['u8', 32] }], ['batch_size', 'u32'], ['metadata', 'string']]],
  ].map(([name, args]) => ({ name, discriminator: Array.from(disc(name)), accounts: [], args: args.map(([n, type]) => ({ name: n, type })) })),
};
const coder = new BorshInstructionCoder(idl);
const authority = Keypair.fromSeed(bytes(32));
const hash = Buffer.from(bytes(32));
const seedName = 'zk-seed';
const metaText = 'sensor:ESP32_001 é';
const clusterTime = 1767225600;
const [pda, bump] = PublicKey.findProgramAddressSync([T(seedName), authority.publicKey.toBuffer()], PROGRAM);
const [batchPda, batchBump] = PublicKey.findProgramAddressSync([T('batch'), T('b-7'), authority.publicKey.toBuffer()], PROGRAM);
const msgHex = (ix) => {
  const tx = new Transaction({ recentBlockhash: blockhash, feePayer: authority.publicKey }).add(ix);
  return hex(tx.serializeMessage());
};
const keys = {
  store: [{ pubkey: pda, isSigner: false, isWritable: true }, { pubkey: authority.publicKey, isSigner: true, isWritable: false }],
  init: [{ pubkey: pda, isSigner: false, isWritable: true }, { pubkey: authority.publicKey, isSigner: true, isWritable: true }, { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }],
  batch: [{ pubkey: batchPda, isSigner: false, isWritable: true }, { pubkey: authority.publicKey, isSigner: true, isWritable: true }, { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }],
};
const enc = (name, args) => coder.encode(name, args);
const mk = (name, args, k) => { const data = enc(name, args); return { name, data: hex(data), message: msgHex(new TransactionInstruction({ programId: PROGRAM, keys: k, data })) }; };
const h32 = Array.from(hash);
out.anchor = {
  program: PROGRAM.toBase58(), authoritySecret: bs58.encode(authority.secretKey), authority: authority.publicKey.toBase58(),
  blockhash, clusterTime, seedName, metadata: metaText, hash: hex(hash), pda: pda.toBase58(), bump, batchId: 'b-7',
  batchPda: batchPda.toBase58(), batchBump,
  discriminators: Object.fromEntries(idl.instructions.map((i) => [i.name, hex(i.discriminator)])),
  calls: {
    initialize: mk('initialize_storage', { seed_name: seedName }, keys.init),
    store: mk('store_commitment', { commitment: h32, metadata: metaText, timestamp: new (await import('bn.js')).default(clusterTime) }, keys.store),
    update: mk('update_commitment', { new_commitment: h32, metadata: metaText, timestamp: new (await import('bn.js')).default(clusterTime) }, keys.store),
    merkle: mk('store_merkle_root', { merkle_root: h32, leaf_count: 37, metadata: metaText }, keys.store),
    batch: mk('store_batch', { batch_root: h32, batch_size: 5, metadata: metaText }, keys.batch),
  },
};
{
  const memoFor = (m) => {
    const ix = new TransactionInstruction({ programId: MEMO, keys: [], data: T(m) });
    return { memo: m, message: msgHex(ix) };
  };
  const c = hex(hash);
  out.memo = { program: MEMO.toBase58(), commitment: c, metadata: 'sensor:ESP32_001',
    plain: memoFor('ZK_COMMITMENT:' + c), withMeta: memoFor('ZK_COMMITMENT:' + c + '|META:sensor:ESP32_001') };
}

writeFileSync(new URL('../vectors_zk.json', import.meta.url), JSON.stringify(out));
