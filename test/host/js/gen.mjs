// Generates reference vectors with @solana/web3.js for the host tests.
// Run: npm install && node gen.mjs > ../vectors.json
import {
  Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, ComputeBudgetProgram,
  TransactionMessage, VersionedTransaction, AddressLookupTableAccount, AddressLookupTableProgram,
} from '@solana/web3.js';
import bs58 from 'bs58';
import {
  getAssociatedTokenAddressSync, createAssociatedTokenAccountIdempotentInstruction,
  createTransferCheckedInstruction, TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
} from '@solana/spl-token';

// deterministic PRNG so the vectors are stable
let s = 0x9e3779b9;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const hex = (b) => Buffer.from(b).toString('hex');
const key = () => new PublicKey(bytes(32));
const kp = () => Keypair.fromSeed(bytes(32));
const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64le = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const str = (x) => { const d = Buffer.from(x, 'utf8'); const l = Buffer.alloc(4); l.writeUInt32LE(d.length); return Buffer.concat([l, d]); };

const out = { pda: [], onCurve: [], tx: [], escrow: [], sendSol: null };

// ---- PDA derivation ---------------------------------------------------------
for (let i = 0; i < 400; i++) {
  const program = key();
  const n = 1 + (rnd() % 3);
  const seeds = Array.from({ length: n }, () => bytes(rnd() % 33));
  const [pda, bump] = PublicKey.findProgramAddressSync(seeds, program);
  out.pda.push({ seeds: seeds.map(hex), program: program.toBase58(), pda: pda.toBase58(), bump });
}
// real P-RaaS seeds (values hardcoded in praas/P-RaaS Device/src/main.cpp)
const PRAAS = new PublicKey('GmHx2yxARZ9ZxQwjceRWMBTXykJo6onZjrkraf4a4zvY');
const NODE = new PublicKey('FgtXBob7pvpxeha8EjEn1Dt8SLhurj845BHRUKZzQddj');
const named = [
  ['praas global_config', [Buffer.from('global_config')]],
  ['praas node_registry', [Buffer.from('node_registry'), NODE.toBuffer()]],
  ...[0, 1, 7, 300, 70000].map((n) => [`praas request ${n}`, [Buffer.from('request'), u64be(n)]]),
];
for (const [name, seeds] of named) {
  const [pda, bump] = PublicKey.findProgramAddressSync(seeds, PRAAS);
  out.pda.push({ name, seeds: seeds.map(hex), program: PRAAS.toBase58(), pda: pda.toBase58(), bump });
}

// ---- isOnCurve -----------------------------------------------------------------
for (let i = 0; i < 1000; i++) {
  const b = i < 50 ? kp().publicKey.toBytes() : bytes(32);
  out.onCurve.push({ key: hex(b), onCurve: PublicKey.isOnCurve(b) });
}

// ---- transactions --------------------------------------------------------------
const blockhash = () => bs58.encode(bytes(32));
function txCase(name, signers, ixs) {
  const tx = new Transaction({ recentBlockhash: blockhash(), feePayer: signers[0].publicKey });
  ixs.forEach((ix) => tx.add(ix));
  tx.sign(...signers);
  out.tx.push({
    name,
    blockhash: tx.recentBlockhash,
    signers: signers.map((k) => bs58.encode(k.secretKey)),
    instructions: ixs.map((ix) => ({
      program: ix.programId.toBase58(),
      data: hex(ix.data),
      accounts: ix.keys.map((k) => ({ key: k.pubkey.toBase58(), signer: k.isSigner, writable: k.isWritable })),
    })),
    message: hex(tx.serializeMessage()),
    tx: tx.serialize().toString('base64'),
  });
}
{
  const a = kp(); const to = key();
  txCase('system transfer', [a], [SystemProgram.transfer({ fromPubkey: a.publicKey, toPubkey: to, lamports: 123456789 })]);
}
{
  // escrow_create-like: writable PDA, writable signer, readonly, system program
  const buyer = kp(); const prog = key();
  txCase('anchor mixed accounts', [buyer], [new TransactionInstruction({
    programId: prog,
    keys: [
      { pubkey: key(), isSigner: false, isWritable: true },
      { pubkey: buyer.publicKey, isSigner: true, isWritable: true },
      { pubkey: key(), isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(bytes(29)),
  })]);
}
{
  // fulfill_request-like: readonly config first, signer readonly last
  const node = kp(); const prog = key();
  txCase('praas fulfill order', [node], [new TransactionInstruction({
    programId: prog,
    keys: [
      { pubkey: key(), isSigner: false, isWritable: false },
      { pubkey: key(), isSigner: false, isWritable: true },
      { pubkey: key(), isSigner: false, isWritable: true },
      { pubkey: node.publicKey, isSigner: true, isWritable: false },
    ],
    data: Buffer.from(bytes(76)),
  })]);
}
{
  const a = kp(); const prog = key();
  txCase('large data 300 bytes', [a], [new TransactionInstruction({
    programId: prog,
    keys: [{ pubkey: a.publicKey, isSigner: true, isWritable: true }, { pubkey: key(), isSigner: false, isWritable: true }],
    data: Buffer.from(bytes(300)),
  })]);
}
{
  const a = kp(); const b = kp(); const prog = key(); const shared = key();
  txCase('two signers two instructions', [a, b], [
    new TransactionInstruction({ programId: prog, keys: [
      { pubkey: shared, isSigner: false, isWritable: false },
      { pubkey: b.publicKey, isSigner: true, isWritable: false },
    ], data: Buffer.from(bytes(10)) }),
    new TransactionInstruction({ programId: SystemProgram.programId, keys: [
      { pubkey: a.publicKey, isSigner: true, isWritable: true },
      { pubkey: shared, isSigner: false, isWritable: true },
    ], data: Buffer.from(bytes(12)) }),
  ]);
}
{
  const a = kp(); const memo = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
  txCase('memo', [a], [new TransactionInstruction({ programId: memo, keys: [], data: Buffer.from('infratic memo test') })]);
}

// sendSol end-to-end (library builds the tx itself)
{
  const a = kp(); const to = key(); const bh = blockhash();
  const tx = new Transaction({ recentBlockhash: bh, feePayer: a.publicKey })
    .add(SystemProgram.transfer({ fromPubkey: a.publicKey, toPubkey: to, lamports: 5000 }));
  tx.sign(a);
  out.sendSol = { secret: bs58.encode(a.secretKey), from: a.publicKey.toBase58(), to: to.toBase58(),
    lamports: 5000, blockhash: bh, tx: tx.serialize().toString('base64') };
}

// ---- escrow account layout (Anchor/Borsh, 300 bytes allocated) ----------------
const ESCROW_SPACE = 8 + 32 + 32 + 8 + (4 + 64) + 1 + 8 + 8 + 1 + 1 + 1 + (4 + 128);
for (const [orderId, proof, status] of [['ord-1', '', 0], ['order-2025-11-08-0001', 'abc', 1],
  ['x'.repeat(64), 'p'.repeat(128), 3], ['order-utf8-éñ', 'f'.repeat(64), 2]]) {
  const buyer = key(); const seller = key();
  const created = 1762600000 + (rnd() % 100000); const expires = created + 3600;
  const body = Buffer.concat([
    Buffer.from(bytes(8)), buyer.toBuffer(), seller.toBuffer(), u64le(250000000), str(orderId),
    Buffer.from([status]), i64le(created), i64le(expires), Buffer.from([254, 1, 0]), str(proof),
  ]);
  const data = Buffer.concat([body, Buffer.alloc(ESCROW_SPACE - body.length)]);
  out.escrow.push({ data: data.toString('base64'), buyer: buyer.toBase58(), seller: seller.toBase58(),
    amount: 250000000, orderId, status, createdAt: created, expiresAt: expires, bump: 254,
    deliveryConfirmed: true, disputeInitiated: false, proofHash: proof });
}
out.escrowSpace = ESCROW_SPACE;
{
  const ESCROW_PROGRAM = new PublicKey('3kk7vGfWwT7Uq7M6uV5cfSyXodbsr7Py6gmBYDCMvstQ');
  const buyer = key(); const orderId = 'order-2025-11-08-0001';
  const [pda, bump] = PublicKey.findProgramAddressSync([Buffer.from('escrow'), Buffer.from(orderId), buyer.toBuffer()], ESCROW_PROGRAM);
  Object.assign(out.escrow[0], { pdaOrderId: orderId, pdaBuyer: buyer.toBase58(), pda: pda.toBase58(), pdaBump: bump });
}

// escrow_create end-to-end: expected instruction built independently here
{
  const { createHash } = await import('node:crypto');
  const disc = (n) => createHash('sha256').update(`global:${n}`).digest().subarray(0, 8);
  const ESCROW_PROGRAM = new PublicKey('3kk7vGfWwT7Uq7M6uV5cfSyXodbsr7Py6gmBYDCMvstQ');
  const buyer = kp(); const seller = key(); const orderId = 'ord-42'; const amount = 1000000; const exp = 3600;
  const [pda, bump] = PublicKey.findProgramAddressSync([Buffer.from('escrow'), Buffer.from(orderId), buyer.publicKey.toBuffer()], ESCROW_PROGRAM);
  const data = Buffer.concat([disc('create_escrow'), u64le(amount), str(orderId), i64le(exp), Buffer.from([bump])]);
  const bh = blockhash();
  const tx = new Transaction({ recentBlockhash: bh, feePayer: buyer.publicKey }).add(new TransactionInstruction({
    programId: ESCROW_PROGRAM, data,
    keys: [
      { pubkey: pda, isSigner: false, isWritable: true },
      { pubkey: buyer.publicKey, isSigner: true, isWritable: true },
      { pubkey: seller, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ] }));
  tx.sign(buyer);
  out.escrowCreate = { secret: bs58.encode(buyer.secretKey), buyer: buyer.publicKey.toBase58(), seller: seller.toBase58(),
    orderId, amount, exp, blockhash: bh, pda: pda.toBase58(), message: hex(tx.serializeMessage()) };
}

// ---- SPL token -----------------------------------------------------------------
out.spl = { ata: [], send: [] };
for (const prog of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
  for (let i = 0; i < 20; i++) {
    const owner = i % 2 ? kp().publicKey : key(); const mint = key();
    out.spl.ata.push({ owner: owner.toBase58(), mint: mint.toBase58(), program: prog.toBase58(),
      ata: getAssociatedTokenAddressSync(mint, owner, true, prog).toBase58() });
  }
  for (const createAta of [true, false]) {
    const from = kp(); const to = key(); const mint = key(); const amount = 1234567890123n; const decimals = 6;
    const src = getAssociatedTokenAddressSync(mint, from.publicKey, true, prog);
    const dst = getAssociatedTokenAddressSync(mint, to, true, prog);
    const bh = blockhash();
    const tx = new Transaction({ recentBlockhash: bh, feePayer: from.publicKey });
    if (createAta) tx.add(createAssociatedTokenAccountIdempotentInstruction(from.publicKey, dst, to, mint, prog));
    tx.add(createTransferCheckedInstruction(src, mint, dst, from.publicKey, amount, decimals, [], prog));
    out.spl.send.push({ secret: bs58.encode(from.secretKey), from: from.publicKey.toBase58(), to: to.toBase58(),
      mint: mint.toBase58(), program: prog.toBase58(), amount: amount.toString(), decimals, createAta,
      blockhash: bh, message: hex(tx.serializeMessage()) });
  }
}

// ---- compute budget ---------------------------------------------------------------
{
  const a = kp(); const to = key(); const bh = blockhash();
  const limit = ComputeBudgetProgram.setComputeUnitLimit({ units: 200000 });
  const price = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 25000 });
  const tx = new Transaction({ recentBlockhash: bh, feePayer: a.publicKey })
    .add(limit).add(price).add(SystemProgram.transfer({ fromPubkey: a.publicKey, toPubkey: to, lamports: 777 }));
  tx.sign(a);
  out.computeBudget = { limitData: hex(limit.data), priceData: hex(price.data), program: limit.programId.toBase58(),
    send: { secret: bs58.encode(a.secretKey), from: a.publicKey.toBase58(), to: to.toBase58(), lamports: 777,
      blockhash: bh, tx: tx.serialize().toString('base64') } };
}

// ---- durable nonce -------------------------------------------------------------------
{
  const seeds = Array.from({ length: 5 }, () => bytes(32));
  const fromSeed = seeds.map((sd) => ({ seed: hex(sd), pub: Keypair.fromSeed(sd).publicKey.toBase58() }));
  const payer = kp(); const nonceKp = kp(); const authority = kp().publicKey; const rent = 1447680; const bh = blockhash();
  const ctx = SystemProgram.createNonceAccount({ fromPubkey: payer.publicKey, noncePubkey: nonceKp.publicKey,
    authorizedPubkey: authority, lamports: rent });
  ctx.recentBlockhash = bh; ctx.feePayer = payer.publicKey;
  const create = { payer: bs58.encode(payer.secretKey), nonce: bs58.encode(nonceKp.secretKey), authority: authority.toBase58(),
    rent, blockhash: bh, message: hex(ctx.serializeMessage()) };

  // nonce account data + a durable transfer with priority fee
  const devKp = kp(); const nonceAcc = key(); const nonceValue = key(); const to = key();
  const data = Buffer.alloc(80); data.writeUInt32LE(0, 0); data.writeUInt32LE(1, 4);
  devKp.publicKey.toBuffer().copy(data, 8); nonceValue.toBuffer().copy(data, 40); data.writeBigUInt64LE(5000n, 72);
  const dtx = new Transaction({ feePayer: devKp.publicKey, nonceInfo: { nonce: nonceValue.toBase58(),
    nonceInstruction: SystemProgram.nonceAdvance({ noncePubkey: nonceAcc, authorizedPubkey: devKp.publicKey }) } });
  dtx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1000 }));
  dtx.add(SystemProgram.transfer({ fromPubkey: devKp.publicKey, toPubkey: to, lamports: 4242 }));
  dtx.sign(devKp);
  out.nonce = { fromSeed, create, account: { address: nonceAcc.toBase58(), data: data.toString('base64'),
    authority: devKp.publicKey.toBase58(), nonce: nonceValue.toBase58(), lamportsPerSignature: 5000 },
    durable: { secret: bs58.encode(devKp.secretKey), to: to.toBase58(), lamports: 4242, message: hex(dtx.serializeMessage()) } };
}

// ---- anchor events -----------------------------------------------------------------
{
  const { createHash } = await import('node:crypto');
  const d8 = (pre, n) => createHash('sha256').update(`${pre}:${n}`).digest().subarray(0, 8);
  const PROG = 'GmHx2yxARZ9ZxQwjceRWMBTXykJo6onZjrkraf4a4zvY';
  const node = key(); const user = key(); const other = key();
  const fulfilled = Buffer.concat([d8('event', 'RequestFulfilled'), u64le(42), node.toBuffer(), str('a1b2c3d4e5'),
    u64le(1000000), i64le(1762600123)]);
  const created = Buffer.concat([d8('event', 'RequestCreated'), u64le(43), user.toBuffer(), node.toBuffer(),
    u64le(1000000), i64le(-5)]);
  const inner = Buffer.concat([d8('event', 'SomethingElse'), u64le(7)]);
  const logs = [
    `Program ${PROG} invoke [1]`,
    'Program log: Instruction: FulfillRequest',
    `Program data: ${fulfilled.toString('base64')}`,
    `Program ${other.toBase58()} invoke [2]`,
    `Program data: ${inner.toString('base64')}`,
    `Program ${other.toBase58()} consumed 100 of 200000 compute units`,
    `Program ${other.toBase58()} success`,
    `Program data: ${created.toString('base64')}`,
    `Program ${PROG} consumed 5000 of 200000 compute units`,
    `Program ${PROG} success`,
  ];
  out.events = { program: PROG, other: other.toBase58(), node: node.toBase58(), user: user.toBase58(), logs,
    fulfilledData: hex(fulfilled.subarray(8)), accountRequest: hex(d8('account', 'Request')),
    eventFulfilled: hex(d8('event', 'RequestFulfilled')) };
}

// ---- versioned transactions + lookup tables --------------------------------------------
{
  const mkTable = (addresses) => new AddressLookupTableAccount({ key: key(), state: {
    deactivationSlot: BigInt('18446744073709551615'), lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0,
    authority: undefined, addresses } });
  const ixJson = (ix) => ({ program: ix.programId.toBase58(), data: hex(ix.data),
    accounts: ix.keys.map((k) => ({ key: k.pubkey.toBase58(), signer: k.isSigner, writable: k.isWritable })) });
  const v0Case = (name, signers, ixs, tables) => {
    const bh = blockhash();
    const msg = new TransactionMessage({ payerKey: signers[0].publicKey, recentBlockhash: bh, instructions: ixs })
      .compileToV0Message(tables);
    const vtx = new VersionedTransaction(msg); vtx.sign(signers);
    return { name, blockhash: bh, signers: signers.map((k) => bs58.encode(k.secretKey)), instructions: ixs.map(ixJson),
      tables: tables.map((t) => ({ key: t.key.toBase58(), addresses: t.state.addresses.map((a) => a.toBase58()) })),
      message: hex(msg.serialize()) };
  };
  const payer = kp(); const progA = key(); const progB = key();
  const w = [key(), key(), key()]; const r = [key(), key(), key()]; const extra = key();
  const t1 = mkTable([key(), w[0], r[0], progB, payer.publicKey, w[1], r[1], key()]);
  const t2 = mkTable([r[1], w[2], r[2], key()]);
  const ix1 = new TransactionInstruction({ programId: progA, data: Buffer.from(bytes(20)), keys: [
    { pubkey: w[0], isSigner: false, isWritable: true }, { pubkey: r[0], isSigner: false, isWritable: false },
    { pubkey: payer.publicKey, isSigner: true, isWritable: true }, { pubkey: extra, isSigner: false, isWritable: true }] });
  const ix2 = new TransactionInstruction({ programId: progB, data: Buffer.from(bytes(5)), keys: [
    { pubkey: w[1], isSigner: false, isWritable: true }, { pubkey: r[1], isSigner: false, isWritable: false },
    { pubkey: w[2], isSigner: false, isWritable: true }, { pubkey: r[2], isSigner: false, isWritable: false }] });
  const second = kp();
  const ix3 = new TransactionInstruction({ programId: progA, data: Buffer.from(bytes(3)), keys: [
    { pubkey: second.publicKey, isSigner: true, isWritable: false }, { pubkey: w[0], isSigner: false, isWritable: true }] });
  const cases = [
    v0Case('one table', [payer], [ix1, ix2], [t1]),
    v0Case('two tables', [payer, second], [ix1, ix2, ix3], [t1, t2]),
    v0Case('no tables', [payer], [ix1], []),
  ];
  // lookup table account data + program instructions
  const table = mkTable([w[0], r[0], extra]);
  const meta = Buffer.alloc(56); meta.writeUInt32LE(1, 0); meta.writeBigUInt64LE(BigInt('18446744073709551615'), 4);
  meta.writeUInt8(1, 21); payer.publicKey.toBuffer().copy(meta, 22);
  const tableData = Buffer.concat([meta, ...table.state.addresses.map((a) => a.toBuffer())]);
  const [createIx, tableAddr] = AddressLookupTableProgram.createLookupTable({ authority: payer.publicKey, payer: payer.publicKey, recentSlot: 123456789 });
  const extendIx = AddressLookupTableProgram.extendLookupTable({ lookupTable: tableAddr, authority: payer.publicKey,
    payer: payer.publicKey, addresses: [w[0], r[0]] });
  out.v0 = { cases, tableAccount: { key: table.key.toBase58(), data: tableData.toString('base64'),
    addresses: table.state.addresses.map((a) => a.toBase58()) },
    create: { authority: payer.publicKey.toBase58(), slot: 123456789, table: tableAddr.toBase58(), ix: ixJson(createIx) },
    extend: { ix: ixJson(extendIx), addresses: [w[0].toBase58(), r[0].toBase58()] } };
}

process.stdout.write(JSON.stringify(out));
