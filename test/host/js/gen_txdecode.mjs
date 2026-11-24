// Reference vectors for ParsedTransaction (parse / sign / decode / cost) from @solana/web3.js.
// Run: node gen_txdecode.mjs > ../vectors_txdecode.json   (output is deterministic)
import {
  Keypair, PublicKey, SystemProgram, TransactionInstruction, ComputeBudgetProgram, TransactionMessage,
  VersionedTransaction, AddressLookupTableAccount,
} from '@solana/web3.js';
import bs58 from 'bs58';
import {
  createTransferCheckedInstruction, createTransferInstruction, createApproveInstruction, createCloseAccountInstruction,
  createMintToInstruction, createBurnInstruction, createAssociatedTokenAccountInstruction,
  createAssociatedTokenAccountIdempotentInstruction, TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID,
} from '@solana/spl-token';

// deterministic PRNG (same pattern as gen.mjs)
let s = 0x2545f491;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const hex = (b) => Buffer.from(b).toString('hex');
const key = () => new PublicKey(bytes(32));
const kp = () => Keypair.fromSeed(bytes(32));
const blockhash = () => bs58.encode(bytes(32));
const b64 = (b) => Buffer.from(b).toString('base64');

const MEMO = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const MEMO_V1 = new PublicKey('Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo');

// ---- independent formatting of the expected strings ---------------------------------
const short = (k) => { const t = k.toString(); return t.slice(0, 4) + '...' + t.slice(-4); };
function units(amount, dec) {
  let d = BigInt(amount).toString();
  if (dec <= 0) return d;
  d = d.padStart(dec + 1, '0');
  const i = d.slice(0, d.length - dec); const f = d.slice(d.length - dec).replace(/0+$/, '');
  return f ? `${i}.${f}` : i;
}
const sol = (l) => `${units(l, 9)} SOL`;

// ---- decoded expectations ----------------------------------------------------------
const pk = (k) => k.toString();
const E = {
  transfer: (ix, from, to, lamports) => [ix, {
    program: 'system', type: 'transfer', known: true, source: pk(from), destination: pk(to), authority: pk(from),
    amount: String(lamports), summary: `Transfer ${sol(lamports)} to ${short(to)}` }],
  createAccount: (ix, from, acc, lamports, space, owner) => [ix, {
    program: 'system', type: 'createAccount', known: true, source: pk(from), destination: pk(acc), amount: String(lamports), owner: pk(owner),
    summary: `Create account ${short(acc)} (${space} bytes, owner ${short(owner)}) funded with ${sol(lamports)}` }],
  nonce: (ix, nonce, auth) => [ix, {
    program: 'system', type: 'advanceNonce', known: true, destination: pk(nonce), authority: pk(auth),
    summary: `Advance nonce account ${short(nonce)}` }],
  limit: (ix, n) => [ix, { program: 'compute-budget', type: 'setComputeUnitLimit', known: true, amount: String(n),
    summary: `Set compute unit limit to ${n}` }],
  price: (ix, n) => [ix, { program: 'compute-budget', type: 'setComputeUnitPrice', known: true, amount: String(n),
    summary: `Set priority fee to ${n} microLamports per compute unit` }],
  memo: (ix, text) => [ix, { program: 'memo', type: 'memo', known: true, text, summary: `Memo: "${text}"` }],
  checked: (ix, prog, src, mint, dst, auth, amount, dec) => [ix, {
    program: prog, type: 'transferChecked', known: true, source: pk(src), mint: pk(mint), destination: pk(dst), authority: pk(auth),
    amount: String(amount), decimals: dec, summary: `Transfer ${units(amount, dec)} tokens (mint ${short(mint)}) to ${short(dst)}` }],
  plain: (ix, prog, src, dst, auth, amount) => [ix, {
    program: prog, type: 'transfer', known: true, source: pk(src), destination: pk(dst), authority: pk(auth), amount: String(amount), decimals: -1,
    summary: `Transfer ${amount} raw token units to ${short(dst)}` }],
  approve: (ix, prog, src, dlg, auth, amount) => [ix, {
    program: prog, type: 'approve', known: true, source: pk(src), destination: pk(dlg), authority: pk(auth), amount: String(amount),
    summary: `Approve ${short(dlg)} to spend up to ${amount} raw token units` }],
  close: (ix, prog, acc, dst, auth) => [ix, {
    program: prog, type: 'closeAccount', known: true, source: pk(acc), destination: pk(dst), authority: pk(auth),
    summary: `Close token account ${short(acc)}, remaining SOL goes to ${short(dst)}` }],
  mintTo: (ix, prog, mint, dst, auth, amount) => [ix, {
    program: prog, type: 'mintTo', known: true, mint: pk(mint), destination: pk(dst), authority: pk(auth), amount: String(amount),
    summary: `Mint ${amount} raw token units (mint ${short(mint)}) to ${short(dst)}` }],
  burn: (ix, prog, acc, mint, auth, amount) => [ix, {
    program: prog, type: 'burn', known: true, source: pk(acc), mint: pk(mint), authority: pk(auth), amount: String(amount),
    summary: `Burn ${amount} raw token units (mint ${short(mint)}) from ${short(acc)}` }],
  ata: (ix, idem, funder, ata, owner, mint) => [ix, {
    program: 'associated-token', type: idem ? 'createIdempotent' : 'create', known: true, source: pk(funder), destination: pk(ata),
    owner: pk(owner), mint: pk(mint), authority: pk(funder),
    summary: `Create token account ${short(ata)} for owner ${short(owner)} (mint ${short(mint)})` }],
  unknown: (ix, prog, nAcc, nData) => [ix, {
    program: 'unknown', type: 'unknown', known: false,
    summary: `Unknown program ${pk(prog)} (${nAcc} accounts, ${nData} bytes of data)` }],
};

// ---- building ---------------------------------------------------------------------
function compile(version, payer, entries, tables) {
  const ixs = entries.map((e) => e[0]);
  const m = new TransactionMessage({ payerKey: payer, recentBlockhash: blockhash(), instructions: ixs });
  return version === 'legacy' ? m.compileToLegacyMessage() : m.compileToV0Message(tables || []);
}

function costOf(signer, entries, numSigs) {
  let limit = null, price = 0n, others = 0, transferred = 0n, funded = 0n;
  for (const [, d] of entries) {
    if (d.program === 'compute-budget') {
      if (d.type === 'setComputeUnitLimit') limit = BigInt(d.amount);
      if (d.type === 'setComputeUnitPrice') price = BigInt(d.amount);
      continue;
    }
    others++;
    if (d.program === 'system' && d.source === pk(signer)) {
      if (d.type === 'transfer') transferred += BigInt(d.amount);
      if (d.type === 'createAccount') funded += BigInt(d.amount);
    }
  }
  const requested = limit !== null;
  if (!requested) limit = BigInt(Math.min(200000 * others, 1400000));
  if (limit > 1400000n) limit = 1400000n;
  const priority = (limit * price + 999999n) / 1000000n;
  const base = BigInt(5000 * numSigs);
  return { signer: pk(signer), baseFee: String(base), priorityFee: String(priority), transferred: String(transferred), funded: String(funded),
    total: String(base + priority + transferred + funded), limit: Number(limit), limitRequested: requested, price: String(price) };
}

const cases = [];
function addCase(name, version, signers, presign, esp, entries, opts = {}) {
  const payer = signers[0].publicKey;
  const msg = compile(version, payer, entries, opts.tables);
  const tx = new VersionedTransaction(msg);
  if (presign.length) tx.sign(presign);
  const before = tx.serialize();
  const after = VersionedTransaction.deserialize(before);
  after.sign([esp]);
  const afterBytes = after.serialize();
  const keys = msg.staticAccountKeys.map(pk);
  const nreq = msg.header.numRequiredSignatures;
  const present = (t) => t.signatures.map((x) => x.some((v) => v !== 0));
  const lookups = (msg.addressTableLookups || []).map((l) => ({
    table: pk(l.accountKey), writable: Array.from(l.writableIndexes), readonly: Array.from(l.readonlyIndexes) }));
  const tables = {};
  for (const t of opts.tables || []) tables[pk(t.key)] = t.state.addresses.map(pk);
  cases.push({
    name, version, base64: b64(before), message: hex(version === 'legacy' ? msg.serialize() : msg.serialize()),
    espSecret: bs58.encode(esp.secretKey), espPubkey: pk(esp.publicKey), espSignerIndex: keys.indexOf(pk(esp.publicKey)),
    header: [nreq, msg.header.numReadonlySignedAccounts, msg.header.numReadonlyUnsignedAccounts],
    staticKeys: keys, blockhash: msg.recentBlockhash,
    instructions: msg.compiledInstructions.map((c) => ({ program: c.programIdIndex, accounts: Array.from(c.accountKeyIndexes), data: hex(c.data) })),
    lookups, tables,
    presentBefore: present(tx), presentAfter: present(after),
    fullySignedAfter: present(after).every((x) => x),
    base64After: b64(afterBytes),
    decoded: entries.map((e) => e[1]),
    cost: costOf(payer, entries, nreq),
    costSigner: pk(payer),
    resolvedDecoded: opts.resolvedDecoded || null,
  });
  return { tx, before, msg };
}

// 1. legacy, two signers, compute budget + transfer + SPL + memo; co-signer pre-signed, device is the fee payer
{
  const A = kp(), B = kp(), to = key(), mint = key(), src = key(), dst = key();
  const l = ComputeBudgetProgram.setComputeUnitLimit({ units: 120000 });
  const p = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 25000 });
  const t = SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 250000000 });
  const c = createTransferCheckedInstruction(src, mint, dst, B.publicKey, 1500000n, 6);
  const m = new TransactionInstruction({ programId: MEMO, keys: [{ pubkey: A.publicKey, isSigner: true, isWritable: false }], data: Buffer.from('order #42 é') });
  addCase('legacy two signers, device is payer', 'legacy', [A, B], [B], A,
    [E.limit(l, 120000), E.price(p, 25000), E.transfer(t, A.publicKey, to, 250000000),
     E.checked(c, 'spl-token', src, mint, dst, B.publicKey, 1500000, 6), E.memo(m, 'order #42 é')]);
}
// 2. legacy, one signer, nothing pre-signed
{
  const A = kp(), to = key();
  const t = SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 5000 });
  addCase('legacy single signer', 'legacy', [A], [], A, [E.transfer(t, A.publicKey, to, 5000)]);
}
// 3. legacy, three signers; device is the middle one, the payer has not signed yet
{
  const A = kp(), B = kp(), C = kp(), newAcc = C, dest = key();
  const ca = SystemProgram.createAccount({ fromPubkey: A.publicKey, newAccountPubkey: newAcc.publicKey, lamports: 2039280, space: 165, programId: TOKEN_PROGRAM_ID });
  const t = SystemProgram.transfer({ fromPubkey: B.publicKey, toPubkey: dest, lamports: 1 });
  addCase('legacy three signers, payer missing', 'legacy', [A, B, C], [C], B,
    [E.createAccount(ca, A.publicKey, newAcc.publicKey, 2039280, 165, TOKEN_PROGRAM_ID), E.transfer(t, B.publicKey, dest, 1)]);
}
// 4. v0 without lookup tables
{
  const A = kp(), B = kp(), to = key();
  const t = SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 1000000000 });
  const t2 = SystemProgram.transfer({ fromPubkey: B.publicKey, toPubkey: to, lamports: 1 });
  addCase('v0 no tables, two signers', 'v0', [A, B], [A], B, [E.transfer(t, A.publicKey, to, 1000000000), E.transfer(t2, B.publicKey, to, 1)]);
}
// 5. v0 with a lookup table: mint and destination token account come from the table
{
  const A = kp(), owner = key(), mint = key(), srcAta = key(), dstAta = key(), other = key(), prog = key();
  const tableKey = key();
  const addresses = [other, srcAta, mint, dstAta, key()];
  const table = new AddressLookupTableAccount({ key: tableKey, state: {
    deactivationSlot: 0xffffffffffffffffn, lastExtendedSlot: 1, lastExtendedSlotStartIndex: 0, authority: undefined, addresses } });
  const c = createTransferCheckedInstruction(srcAta, mint, dstAta, A.publicKey, 42n, 9, [], TOKEN_2022_PROGRAM_ID);
  const u = new TransactionInstruction({ programId: prog, keys: [{ pubkey: other, isSigner: false, isWritable: true }], data: Buffer.from([1, 2, 3]) });
  const entries = [E.checked(c, 'token-2022', srcAta, mint, dstAta, A.publicKey, 42, 9), E.unknown(u, prog, 1, 3)];
  const r = addCase('v0 lookup table', 'v0', [A], [], A, entries, { tables: [table] });
  // instruction 0 touches only table accounts: without the table the summary falls back to a marker
  const cs = cases[cases.length - 1];
  cs.unresolvedDecoded = [
    { program: 'token-2022', type: 'transferChecked', known: true, resolved: false, amount: '42', decimals: 9, source: '', mint: '', destination: '' },
    { program: 'unknown', type: 'unknown', known: false, resolved: false },
  ];
}
// 6. every decoder: one signer, legacy
{
  const A = kp(), to = key(), mint = key(), src = key(), dst = key(), dlg = key(), nonce = key(), prog = key(), wallet = key(), ata = key();
  const e = [
    E.nonce(SystemProgram.nonceAdvance({ noncePubkey: nonce, authorizedPubkey: A.publicKey }), nonce, A.publicKey),
    E.plain(createTransferInstruction(src, dst, A.publicKey, 1000n), 'spl-token', src, dst, A.publicKey, 1000),
    E.checked(createTransferCheckedInstruction(src, mint, dst, A.publicKey, 123456789n, 2, [], TOKEN_2022_PROGRAM_ID), 'token-2022', src, mint, dst, A.publicKey, 123456789, 2),
    E.checked(createTransferCheckedInstruction(src, mint, dst, A.publicKey, 100n, 0), 'spl-token', src, mint, dst, A.publicKey, 100, 0),
    E.approve(createApproveInstruction(src, dlg, A.publicKey, 777n), 'spl-token', src, dlg, A.publicKey, 777),
    E.close(createCloseAccountInstruction(src, dst, A.publicKey, [], TOKEN_2022_PROGRAM_ID), 'token-2022', src, dst, A.publicKey),
    E.mintTo(createMintToInstruction(mint, dst, A.publicKey, 5n), 'spl-token', mint, dst, A.publicKey, 5),
    E.burn(createBurnInstruction(src, mint, A.publicKey, 9n), 'spl-token', src, mint, A.publicKey, 9),
    E.ata(createAssociatedTokenAccountInstruction(A.publicKey, ata, wallet, mint), false, A.publicKey, ata, wallet, mint),
    E.ata(createAssociatedTokenAccountIdempotentInstruction(A.publicKey, ata, wallet, mint), true, A.publicKey, ata, wallet, mint),
    E.memo(new TransactionInstruction({ programId: MEMO_V1, keys: [], data: Buffer.from('legacy memo') }), 'legacy memo'),
    E.unknown(new TransactionInstruction({ programId: prog, keys: [{ pubkey: dst, isSigner: false, isWritable: true }], data: Buffer.from([9, 9]) }), prog, 1, 2),
    E.transfer(SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 1 }), A.publicKey, to, 1),
    E.transfer(SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 123456789012 }), A.publicKey, to, 123456789012),
  ];
  // system Assign (tag 1): known program, instruction not decoded
  e.push([SystemProgram.assign({ accountPubkey: A.publicKey, programId: prog }), { program: 'system', type: 'unknown', known: false }]);
  addCase('all decoders', 'legacy', [A], [], A, e);
}
// 7. priority fee rounding and default compute estimate (no limit instruction)
{
  const A = kp(), to = key();
  const p = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 });
  const t = SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 10 });
  addCase('default compute estimate', 'legacy', [A], [], A, [E.price(p, 1), E.transfer(t, A.publicKey, to, 10)]);
}

// ---- negative cases ---------------------------------------------------------------
const cu16 = (n) => { const o = []; do { let b = n & 0x7f; n >>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
const cat = (...a) => Buffer.concat(a.map((x) => Buffer.from(x)));
// minimal raw builder, so each field can be broken on its own
function raw(o = {}) {
  const keys = o.keys || [bytes(32), bytes(32), bytes(32)].map((b, i) => (i === 2 ? Uint8Array.from(Array(32).fill(7)) : b));
  const sigs = o.sigs || [new Uint8Array(64)];
  const header = o.header || [1, 0, 1];
  const ixs = o.ixs || [{ prog: 2, accts: [0, 1], data: [2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0] }];
  const parts = [o.sigCount !== undefined ? o.sigCount : cu16(sigs.length), ...sigs];
  if (o.version !== undefined) parts.push([o.version]);
  parts.push(header, o.keyCount !== undefined ? o.keyCount : cu16(keys.length), ...keys, o.blockhash || new Uint8Array(32));
  parts.push(o.ixCount !== undefined ? o.ixCount : cu16(ixs.length));
  for (const ix of ixs) parts.push([ix.prog], cu16(ix.accts.length), ix.accts, cu16(ix.data.length), ix.data);
  if (o.lookups) { parts.push(cu16(o.lookups.length)); for (const l of o.lookups) parts.push(l.table, cu16(l.w.length), l.w, cu16(l.r.length), l.r); }
  if (o.tail) parts.push(o.tail);
  return cat(...parts);
}
const good = raw();
const goodV0 = raw({ version: 0x80, lookups: [{ table: bytes(32), w: [0], r: [1] }], ixs: [{ prog: 2, accts: [0, 1, 3, 4], data: [1, 2] }] });
const negatives = [];
const neg = (name, b) => negatives.push({ name, hex: hex(b) });
const posRaw = [['legacy minimal', good], ['v0 minimal', goodV0]].map(([name, b]) => ({ name, hex: hex(b) }));
neg('empty', Buffer.alloc(0));
neg('trailing byte', cat(good, [0]));
neg('trailing byte v0', cat(goodV0, [0]));
neg('non-canonical sig count', raw({ sigCount: [0x81, 0x00] }));
neg('sig count continuation never ends', cat([0x80, 0x80, 0x80, 0x80], good));
neg('sig count too large for 16 bits', raw({ sigCount: [0xff, 0xff, 0x04] }));
neg('zero signatures', raw({ sigs: [], sigCount: [0] }));
neg('too many signatures', raw({ sigs: Array.from({ length: 20 }, () => new Uint8Array(64)), header: [20, 0, 1] }));
neg('header sig count mismatch', raw({ header: [2, 0, 1] }));
neg('fee payer readonly', raw({ header: [1, 1, 1] }));
neg('zero required signatures', raw({ header: [0, 0, 1], sigs: [], sigCount: [0] }));
neg('header exceeds keys', raw({ header: [1, 0, 3] }));
neg('unsupported version', raw({ version: 0x81 }));
neg('key count huge', raw({ keyCount: [0xff, 0xff, 0x03] }));
neg('key count more than 256', raw({ keyCount: cu16(300) }));
neg('instruction count huge', raw({ ixCount: [0xff, 0xff, 0x03] }));
neg('program index out of range', raw({ ixs: [{ prog: 3, accts: [0, 1], data: [2] }] }));
neg('program index is fee payer', raw({ ixs: [{ prog: 0, accts: [1], data: [2] }] }));
neg('account index out of range', raw({ ixs: [{ prog: 2, accts: [0, 3], data: [2] }] }));
neg('account index 255', raw({ ixs: [{ prog: 2, accts: [255], data: [] }] }));
neg('v0 lookup index loads beyond limit', raw({ version: 0x80, lookups: [{ table: bytes(32), w: Array(200).fill(1), r: Array(100).fill(2) }] }));
neg('v0 program from lookup table', raw({ version: 0x80, lookups: [{ table: bytes(32), w: [0], r: [] }], ixs: [{ prog: 3, accts: [0], data: [] }] }));
neg('v0 account index past loaded accounts', raw({ version: 0x80, lookups: [{ table: bytes(32), w: [0], r: [1] }], ixs: [{ prog: 2, accts: [5], data: [] }] }));
neg('v0 truncated lookup', raw({ version: 0x80, lookups: [{ table: bytes(32), w: [0], r: [1] }] }).subarray(0, -1));
neg('legacy message with lookups tail', raw({ tail: [1, 2, 3] }));
{
  const big = raw({ ixs: [{ prog: 2, accts: [0, 1], data: Array(1500).fill(0) }] });
  neg('oversized (valid structure, 1500+ bytes)', big);
}
// the largest valid size is accepted
const max = raw({ ixs: [{ prog: 2, accts: [0, 1], data: Array(1232 - raw({ ixs: [{ prog: 2, accts: [0, 1], data: [] }] }).length - 1).fill(5) }] });
const maxHex = hex(max);

// sanity: our raw builder matches web3.js for a real transaction, so the negatives are built on the real format
{
  const A = kp(); const to = key();
  const bh = blockhash();
  const msg = new TransactionMessage({ payerKey: A.publicKey, recentBlockhash: bh, instructions: [SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 1 })] }).compileToLegacyMessage();
  const vt = new VersionedTransaction(msg);
  const ours = raw({ keys: msg.staticAccountKeys.map((k) => k.toBytes()), blockhash: bs58.decode(bh), header: [1, 0, 1],
    ixs: [{ prog: 2, accts: [0, 1], data: Array.from(SystemProgram.transfer({ fromPubkey: A.publicKey, toPubkey: to, lamports: 1 }).data) }] });
  if (hex(ours) !== hex(vt.serialize())) throw new Error('raw builder differs from web3.js');
}

neg("oversized (1233 bytes exactly)", cat(max, [0]));
const bad64 = ['', '!!!!', 'AQ', 'A'.repeat(2000), b64(good).slice(0, -3)];

process.stdout.write(JSON.stringify({ cases, negatives, positives: posRaw, maxHex, bad64 }, null, 1) + '\n');
