// Reference vectors for the instruction builders, made with the official @solana/web3.js and @solana/spl-token.
// Run: node gen_instructions.mjs   (writes ../vectors_instructions.json)
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction,
} from '@solana/web3.js';
import {
  TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, AuthorityType, NATIVE_MINT, NATIVE_MINT_2022,
  createInitializeMint2Instruction, createInitializeAccount3Instruction, createTransferInstruction,
  createMintToInstruction, createMintToCheckedInstruction, createBurnInstruction, createBurnCheckedInstruction,
  createApproveInstruction, createApproveCheckedInstruction, createRevokeInstruction, createCloseAccountInstruction,
  createSetAuthorityInstruction, createSyncNativeInstruction, createFreezeAccountInstruction,
  createThawAccountInstruction, createAssociatedTokenAccountInstruction,
  createAssociatedTokenAccountIdempotentInstruction, getAssociatedTokenAddressSync,
} from '@solana/spl-token';

// deterministic PRNG so the vectors are stable
let s = 0x2545f491;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const hex = (b) => Buffer.from(b).toString('hex');
const kp = () => Keypair.fromSeed(bytes(32));
const key = () => kp().publicKey;
const b58 = (k) => k.toBase58();
const U64_MAX = (1n << 64n) - 1n;

const out = { ix: [], seeds: [], badSeeds: [], wrap: null, unwrap: null };

function dump(ix) {
  return {
    program: b58(ix.programId),
    accounts: ix.keys.map((k) => ({ pubkey: b58(k.pubkey), signer: k.isSigner, writable: k.isWritable })),
    data: hex(ix.data),
  };
}
// args: k = pubkeys (base58), u = u64 decimal strings, d = decimals, seed, t = authority type, none = no optional key
const add = (name, ix, args) => out.ix.push({ name, args, ...dump(ix) });
const ks = (...a) => a.map(b58);
const amounts = [0n, 1n, 1500000n, 0x0102030405060708n, U64_MAX];

// ---- System program ---------------------------------------------------------
for (let i = 0; i < 5; i++) {
  const a = amounts[i];
  const an = a > (1n << 52n) ? (1n << 52n) + BigInt(i) : a; // web3.js createAccount* take JS numbers: stay below 2^53
  const [from, to, newAcc, owner, base, seedOwner] = Array.from({ length: 6 }, key);
  const space = BigInt(rnd() % 10240) + (i === 4 ? U64_MAX - 10240n : 0n);
  const seed = ['', 'a', 'stake:0', 'héllo-wörld', 'x'.repeat(32)][i];
  add('sys.transfer', SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: a }), { k: ks(from, to), u: [String(a)] });
  add('sys.createAccount', SystemProgram.createAccount({ fromPubkey: from, newAccountPubkey: newAcc, lamports: Number(an), space: Number(space % 100000n), programId: owner }),
    { k: ks(from, newAcc, owner), u: [String(an), String(space % 100000n)] });
  add('sys.assign', SystemProgram.assign({ accountPubkey: from, programId: owner }), { k: ks(from, owner) });
  add('sys.allocate', SystemProgram.allocate({ accountPubkey: from, space: Number(space % 100000n) }), { k: ks(from), u: [String(space % 100000n)] });
  for (const sameBase of [false, true]) {
    const b = sameBase ? from : base;
    add('sys.createAccountWithSeed', SystemProgram.createAccountWithSeed({
      fromPubkey: from, newAccountPubkey: newAcc, basePubkey: b, seed, lamports: Number(an), space: Number(space % 100000n), programId: owner,
    }), { k: ks(from, newAcc, b, owner), u: [String(an), String(space % 100000n)], seed });
  }
  add('sys.transferWithSeed', SystemProgram.transfer({
    fromPubkey: from, basePubkey: base, toPubkey: to, lamports: a, seed, programId: seedOwner,
  }), { k: ks(from, base, seedOwner, to), u: [String(a)], seed });
}

// ---- createWithSeed ---------------------------------------------------------
for (const seed of ['', 'a', 'vault', 'héllo', 'x'.repeat(32), 'y'.repeat(31)]) {
  const base = key(), prog = key();
  out.seeds.push({ base: b58(base), seed, program: b58(prog), address: b58(await PublicKey.createWithSeed(base, seed, prog)) });
}
out.seeds.push({ base: b58(key()), seed: 'abc', program: b58(TOKEN_PROGRAM_ID), address: '' });
out.seeds[out.seeds.length - 1].address = b58(await PublicKey.createWithSeed(new PublicKey(out.seeds[out.seeds.length - 1].base), 'abc', TOKEN_PROGRAM_ID));
out.badSeeds.push({ base: b58(key()), seed: 'z'.repeat(33), program: b58(key()) });
// an owner whose 32 bytes end in the PDA marker (the runtime, and web3.js, reject it)
out.badSeeds.push({ base: b58(key()), seed: 'ok', programHex: hex(Buffer.concat([Buffer.alloc(11), Buffer.from('ProgramDerivedAddress')])) });

// ---- SPL Token and Token-2022 -------------------------------------------------
for (const prog of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
  const P = b58(prog);
  const tag = (n) => `${n}`;
  for (let i = 0; i < 5; i++) {
    const a = amounts[i];
    const dec = [0, 6, 9, 18, 255][i];
    const [mint, acc, dst, owner, delegate, auth, freezeAuth, newAuth] = Array.from({ length: 8 }, key);
    const base = { p: P };
    const A = (extra) => ({ ...base, ...extra });

    add(tag('tok.initializeMint2'), createInitializeMint2Instruction(mint, dec, auth, freezeAuth, prog), A({ k: ks(mint, auth, freezeAuth), d: dec, none: false }));
    add(tag('tok.initializeMint2'), createInitializeMint2Instruction(mint, dec, auth, null, prog), A({ k: ks(mint, auth), d: dec, none: true }));
    add('tok.initializeAccount3', createInitializeAccount3Instruction(acc, mint, owner, prog), A({ k: ks(acc, mint, owner) }));
    add('tok.transfer', createTransferInstruction(acc, dst, owner, a, [], prog), A({ k: ks(acc, dst, owner), u: [String(a)] }));
    add('tok.mintTo', createMintToInstruction(mint, dst, auth, a, [], prog), A({ k: ks(mint, dst, auth), u: [String(a)] }));
    add('tok.mintToChecked', createMintToCheckedInstruction(mint, dst, auth, a, dec, [], prog), A({ k: ks(mint, dst, auth), u: [String(a)], d: dec }));
    add('tok.burn', createBurnInstruction(acc, mint, owner, a, [], prog), A({ k: ks(acc, mint, owner), u: [String(a)] }));
    add('tok.burnChecked', createBurnCheckedInstruction(acc, mint, owner, a, dec, [], prog), A({ k: ks(acc, mint, owner), u: [String(a)], d: dec }));
    add('tok.approve', createApproveInstruction(acc, delegate, owner, a, [], prog), A({ k: ks(acc, delegate, owner), u: [String(a)] }));
    add('tok.approveChecked', createApproveCheckedInstruction(acc, mint, delegate, owner, a, dec, [], prog), A({ k: ks(acc, mint, delegate, owner), u: [String(a)], d: dec }));
    add('tok.revoke', createRevokeInstruction(acc, owner, [], prog), A({ k: ks(acc, owner) }));
    add('tok.closeAccount', createCloseAccountInstruction(acc, dst, owner, [], prog), A({ k: ks(acc, dst, owner) }));
    add('tok.syncNative', createSyncNativeInstruction(acc, prog), A({ k: ks(acc) }));
    add('tok.freezeAccount', createFreezeAccountInstruction(acc, mint, freezeAuth, [], prog), A({ k: ks(acc, mint, freezeAuth) }));
    add('tok.thawAccount', createThawAccountInstruction(acc, mint, freezeAuth, [], prog), A({ k: ks(acc, mint, freezeAuth) }));
    // every authority type, with a new authority and with None
    for (const t of [0, 1, 2, 3, 4 + i * 2]) {
      add('tok.setAuthority', createSetAuthorityInstruction(acc, auth, t, newAuth, [], prog), A({ k: ks(acc, auth, newAuth), t, none: false }));
      add('tok.setAuthority', createSetAuthorityInstruction(acc, auth, t, null, [], prog), A({ k: ks(acc, auth), t, none: true }));
    }
    // associated token account (create + idempotent) for a wallet-style owner
    const ownerKp = kp().publicKey;
    const ata = getAssociatedTokenAddressSync(mint, ownerKp, false, prog);
    add('ata.create', createAssociatedTokenAccountInstruction(owner, ata, ownerKp, mint, prog), A({ k: ks(owner, ata, ownerKp, mint) }));
    add('ata.createIdempotent', createAssociatedTokenAccountIdempotentInstruction(owner, ata, ownerKp, mint, prog), A({ k: ks(owner, ata, ownerKp, mint) }));
  }
}

// ---- Memo (no spl-memo package: same layout as @solana/spl-memo) -----------------
const MEMO = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const memoIx = (text, signers) => new TransactionInstruction({
  keys: signers.map((k) => ({ pubkey: k, isSigner: true, isWritable: false })), programId: MEMO, data: Buffer.from(text, 'utf8'),
});
for (const [text, n] of [['hello', 0], ['', 0], ['signed memo ✓', 1], ['two signers', 2]]) {
  const sg = Array.from({ length: n }, key);
  add('memo', memoIx(text, sg), { k: ks(...sg), seed: text });
}

// ---- wrapSol / unwrapSol transactions ---------------------------------------------
const BH = '4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM';
const ownerKp = kp();
out.owner = b58(ownerKp.publicKey);
out.ownerSecret = (await import('bs58')).default.encode(ownerKp.secretKey);
out.blockhash = BH;
for (const prog of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
  const native = prog.equals(TOKEN_2022_PROGRAM_ID) ? NATIVE_MINT_2022 : NATIVE_MINT;
  const ata = getAssociatedTokenAddressSync(native, ownerKp.publicKey, false, prog);
  const w = new Transaction({ feePayer: ownerKp.publicKey, recentBlockhash: BH });
  w.add(createAssociatedTokenAccountIdempotentInstruction(ownerKp.publicKey, ata, ownerKp.publicKey, native, prog));
  w.add(SystemProgram.transfer({ fromPubkey: ownerKp.publicKey, toPubkey: ata, lamports: 123456789 }));
  w.add(createSyncNativeInstruction(ata, prog));
  const u = new Transaction({ feePayer: ownerKp.publicKey, recentBlockhash: BH });
  u.add(createCloseAccountInstruction(ata, ownerKp.publicKey, ownerKp.publicKey, [], prog));
  (out.wrapTx ??= []).push({
    program: b58(prog), lamports: 123456789,
    wrapMessage: hex(w.serializeMessage()), unwrapMessage: hex(u.serializeMessage()),
  });
}

const here = path.dirname(fileURLToPath(import.meta.url));
fs.writeFileSync(path.join(here, '..', 'vectors_instructions.json'), JSON.stringify(out, null, 1) + '\n');
