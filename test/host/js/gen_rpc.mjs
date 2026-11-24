// Reference vectors for the extra RPC methods (Infratic-rpc.cpp).
// The mock answers are fed to the official @solana/web3.js Connection through a fake fetch:
// web3.js validates the answer shape, records the request it would send and parses the result.
// The C++ tests replay the same answers and compare requests and parsed values.
// Run: node gen_rpc.mjs   (writes ../vectors_rpc.json, deterministic)
import { Connection, Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js';
import bs58 from 'bs58';
import { writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

let s = 0x51f15e;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const hex = (b) => Buffer.from(b).toString('hex');
const key = () => new PublicKey(bytes(32));
const sig = () => bs58.encode(bytes(64));

// Connection whose HTTP layer returns `answer` and records the last request body
function mockConn(answer) {
  const rec = { body: null };
  const fetchFn = async (url, init) => {
    rec.body = JSON.parse(init.body);
    const resp = typeof answer === 'function' ? answer(rec.body) : answer;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: rec.body.id, ...resp }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  };
  return { conn: new Connection('https://mock.rpc', { fetch: fetchFn, commitment: 'confirmed' }), rec };
}
const req = (rec) => ({ method: rec.body.method, params: rec.body.params });
// answers are stored as JSON strings (like on the wire; also keeps the vector file shallow)
const ctx = (v) => ({ result: { context: { slot: 1000 }, value: v } });

const out = {};

// ---- getSlot / getHealth / getVersion ------------------------------------------------
{
  const a = { result: 311222333 };
  const { conn, rec } = mockConn(a);
  const slot = await conn.getSlot('confirmed');
  out.getSlot = { request: req(rec), response: a, expected: slot };
  const v = { result: { 'solana-core': '2.1.14', 'feature-set': 3294202862 } };
  const m2 = mockConn(v);
  const ver = await m2.conn.getVersion();
  out.getVersion = { request: req(m2.rec), response: v, expected: ver['solana-core'] };
  out.getHealth = { request: { method: 'getHealth', params: [] } };
}

// ---- getBalance with commitment --------------------------------------------------------
{
  const k = key();
  const a = ctx(2039280);
  const { conn, rec } = mockConn(a);
  const bal = await conn.getBalance(k, 'finalized');
  out.getBalance = { key: k.toBase58(), request: req(rec), response: a, expected: bal };
}

// ---- getAccountInfo / getMultipleAccounts ----------------------------------------------
const accJson = (data, lamports, owner, rentEpoch, executable = false) =>
  ({ data: [Buffer.from(data).toString('base64'), 'base64'], executable, lamports, owner: owner.toBase58(), rentEpoch, space: data.length });
const accExpected = (info) => info == null ? { exists: false } : {
  exists: true, lamports: info.lamports, owner: info.owner.toBase58(), executable: info.executable,
  rentEpoch: info.rentEpoch, dataHex: hex(info.data),
};
{
  const k = key();
  const a = ctx(accJson(bytes(40), 1461600, key(), 361, true));
  const { conn, rec } = mockConn(a);
  const info = await conn.getAccountInfo(k, 'confirmed');
  out.getAccountInfo = { key: k.toBase58(), request: req(rec), response: a, expected: accExpected(info) };
  const nul = ctx(null);
  const m2 = mockConn(nul);
  const info2 = await m2.conn.getAccountInfo(k, 'confirmed');
  out.getAccountInfoNull = { key: k.toBase58(), response: nul, expected: accExpected(info2) };
}
{
  const keys = Array.from({ length: 3 }, key);
  const owner = key();
  const vals = [accJson(bytes(8), 5, owner, 100), null, accJson(new Uint8Array(0), 890880, owner, 361)];
  const a = ctx(vals);
  const { conn, rec } = mockConn(a);
  const infos = await conn.getMultipleAccountsInfo(keys, 'confirmed');
  out.getMultipleAccounts = {
    keys: keys.map((x) => x.toBase58()), request: req(rec), response: a, expected: infos.map(accExpected),
  };

  // 250 keys -> web3.js has no chunking, so ask it for each slice of 100 the library has to send
  const many = Array.from({ length: 250 }, key);
  const chunks = [];
  for (let i = 0; i < many.length; i += 100) {
    const part = many.slice(i, i + 100);
    const answer = ctx(part.map((_, j) => ((i + j) % 7 === 0 ? null : accJson(Uint8Array.of((i + j) & 0xff), i + j + 1, owner, 1))));
    const m = mockConn(answer);
    const res = await m.conn.getMultipleAccountsInfo(part, 'confirmed');
    chunks.push({ request: req(m.rec), response: answer, expected: res.map(accExpected) });
  }
  out.getMultipleAccountsMany = { keys: many.map((x) => x.toBase58()), chunks };
}

// ---- getTokenAccountsByOwner (jsonParsed) ---------------------------------------------
{
  const owner = key();
  const tokenProgram = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
  const t22 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
  const parsed = (mint, amount, decimals, ui, state, prog) => ({
    data: { parsed: { info: { isNative: false, mint: mint.toBase58(), owner: owner.toBase58(), state,
      tokenAmount: { amount, decimals, uiAmount: Number(ui), uiAmountString: ui } }, type: 'account' },
      program: prog === tokenProgram ? 'spl-token' : 'spl-token-2022', space: 165 },
    executable: false, lamports: 2039280, owner: prog.toBase58(), rentEpoch: 361, space: 165,
  });
  for (const [name, prog] of [['getTokenAccountsByOwner', tokenProgram], ['getTokenAccountsByOwner2022', t22]]) {
    const items = [
      { pubkey: key().toBase58(), account: parsed(key(), '1500000', 6, '1.5', 'initialized', prog) },
      { pubkey: key().toBase58(), account: parsed(key(), '18446744073709551615', 9, '18446744073.709551615', 'frozen', prog) },
      { pubkey: key().toBase58(), account: parsed(key(), '0', 0, '0', 'initialized', prog) },
    ];
    if (prog === t22) {
      // extensions nest deeper than ArduinoJson's default limit (10)
      items[0].account.data.parsed.info.extensions = [
        { extension: 'transferFeeAmount', state: { withheldAmount: 0 } },
        { extension: 'immutableOwner' },
        { extension: 'memoTransfer', state: { requireIncomingTransferMemos: { nested: { deeper: true } } } },
      ];
    }
    const a = ctx(items);
    const { conn, rec } = mockConn(a);
    const res = await conn.getParsedTokenAccountsByOwner(owner, { programId: prog }, 'confirmed');
    out[name] = {
      owner: owner.toBase58(), program: prog.toBase58(), request: req(rec), response: a,
      expected: res.value.map((v) => ({
        address: v.pubkey.toBase58(), mint: v.account.data.parsed.info.mint, owner: v.account.data.parsed.info.owner,
        amount: v.account.data.parsed.info.tokenAmount.amount, decimals: v.account.data.parsed.info.tokenAmount.decimals,
        uiAmount: v.account.data.parsed.info.tokenAmount.uiAmountString, frozen: v.account.data.parsed.info.state === 'frozen',
      })),
    };
  }
}

// ---- getTokenSupply -------------------------------------------------------------------
{
  const mint = key();
  const a = ctx({ amount: '999999999000000', decimals: 6, uiAmount: 999999999, uiAmountString: '999999999' });
  const { conn, rec } = mockConn(a);
  const res = await conn.getTokenSupply(mint, 'confirmed');
  out.getTokenSupply = { mint: mint.toBase58(), request: req(rec), response: a, expected: { amount: res.value.amount, decimals: res.value.decimals } };
}

// ---- getSignatureStatuses -------------------------------------------------------------
{
  const sigs = [sig(), sig(), sig(), sig()];
  const vals = [
    { slot: 300, confirmations: null, err: null, status: { Ok: null }, confirmationStatus: 'finalized' },
    null,
    { slot: 301, confirmations: 5, err: { InstructionError: [2, { Custom: 6001 }] }, status: { Err: { InstructionError: [2, { Custom: 6001 }] } }, confirmationStatus: 'confirmed' },
    { slot: 302, confirmations: 0, err: 'BlockhashNotFound', status: { Err: 'BlockhashNotFound' }, confirmationStatus: 'processed' },
  ];
  const a = ctx(vals);
  const { conn, rec } = mockConn(a);
  const res = await conn.getSignatureStatuses(sigs);
  out.getSignatureStatuses = {
    sigs, request: req(rec), response: a,
    expected: res.value.map((v) => v == null ? { found: false } :
      { found: true, slot: v.slot, confirmationStatus: v.confirmationStatus, failed: v.err != null, err: v.err == null ? '' : JSON.stringify(v.err) }),
  };
  const m2 = mockConn(a);
  await m2.conn.getSignatureStatuses(sigs, { searchTransactionHistory: true });
  out.getSignatureStatusesHistory = { request: req(m2.rec) };
}

// ---- getTransaction -------------------------------------------------------------------
{
  const payer = key(), dest = key();
  const mk = (extra) => {
    const sigStr = sig();
    return {
      sigStr,
      resp: {
        result: {
          slot: 312000000, blockTime: 1762600123,
          meta: {
            err: null, fee: 5000, innerInstructions: [], loadedAddresses: { readonly: [], writable: [] },
            logMessages: ['Program 11111111111111111111111111111111 invoke [1]', 'Program 11111111111111111111111111111111 success'],
            postBalances: [999995000, 1000000, 1], preBalances: [2000000000, 0, 1], postTokenBalances: [], preTokenBalances: [], rewards: [], status: { Ok: null },
            computeUnitsConsumed: 150,
            ...extra.meta,
          },
          transaction: {
            message: {
              accountKeys: [payer.toBase58(), dest.toBase58(), '11111111111111111111111111111111'],
              header: { numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 1, numRequiredSignatures: 1 },
              instructions: [{ accounts: [0, 1], data: bs58.encode(Uint8Array.of(2, 0, 0, 0, 64, 66, 15, 0, 0, 0, 0, 0)), programIdIndex: 2, stackHeight: null }],
              recentBlockhash: bs58.encode(bytes(32)),
              ...extra.message,
            },
            signatures: [sigStr],
          },
          version: extra.version,
        },
      },
    };
  };
  const expectTx = (r, versioned) => {
    const keys = r.transaction.message.getAccountKeys({ accountKeysFromLookups: r.meta.loadedAddresses }).keySegments().flat();
    return {
      found: true, slot: r.slot, blockTime: r.blockTime, fee: r.meta.fee, failed: r.meta.err != null,
      err: r.meta.err == null ? '' : JSON.stringify(r.meta.err),
      preBalances: r.meta.preBalances, postBalances: r.meta.postBalances,
      accountKeys: keys.map((k) => k.toBase58()), logs: r.meta.logMessages,
    };
  };
  const run = async (name, extra, versioned) => {
    const { sigStr, resp } = mk(extra);
    const { conn, rec } = mockConn(resp);
    const r = await conn.getTransaction(sigStr, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
    out[name] = { sig: sigStr, request: req(rec), response: resp, expected: expectTx(r, versioned) };
  };
  await run('getTransaction', { version: 'legacy', meta: {}, message: {} });
  await run('getTransactionFailed', { version: 'legacy', meta: { err: { InstructionError: [0, 'InsufficientFunds'] }, status: { Err: { InstructionError: [0, 'InsufficientFunds'] } }, logMessages: ['Program log: ' + 'x'.repeat(900)] }, message: {} });
  const l1 = key(), l2 = key();
  await run('getTransactionV0', {
    version: 0, meta: { loadedAddresses: { writable: [l1.toBase58()], readonly: [l2.toBase58()] }, postBalances: [1, 2, 3, 4, 5], preBalances: [1, 2, 3, 4, 6] },
    message: { addressTableLookups: [{ accountKey: key().toBase58(), readonlyIndexes: [3], writableIndexes: [1] }] },
  }, true);
  const sigStr = sig();
  const nul = { result: null };
  const { conn } = mockConn(nul);
  const r = await conn.getTransaction(sigStr, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
  out.getTransactionNull = { sig: sigStr, response: nul, webjsNull: r === null };
}

// ---- requestAirdrop ---------------------------------------------------------------------
{
  const k = key();
  const a = { result: sig() };
  const { conn, rec } = mockConn(a);
  const res = await conn.requestAirdrop(k, 1000000000);
  out.requestAirdrop = { key: k.toBase58(), lamports: 1000000000, request: req(rec), response: a, expected: res };
}

// ---- getFeeForMessage --------------------------------------------------------------------
{
  const payer = Keypair.fromSeed(bytes(32));
  const tx = new Transaction({ recentBlockhash: bs58.encode(bytes(32)), feePayer: payer.publicKey });
  tx.add(SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: key(), lamports: 12345 }));
  const msg = tx.compileMessage();
  const b64 = Buffer.from(msg.serialize()).toString('base64');
  const a = ctx(5000);
  const { conn, rec } = mockConn(a);
  const res = await conn.getFeeForMessage(msg, 'confirmed');
  const nul = ctx(null);
  const m2 = mockConn(nul);
  const res2 = await m2.conn.getFeeForMessage(msg, 'confirmed');
  out.getFeeForMessage = { message: b64, request: req(rec), response: a, expected: res.value, nullResponse: nul, nullExpected: res2.value };
}

// responses go into the file as strings, exactly as the mock HTTP server returns them
const strResponses = (o) => {
  if (Array.isArray(o)) o.forEach(strResponses);
  else if (o && typeof o === 'object') {
    for (const k of Object.keys(o)) {
      if ((k === 'response' || k === 'nullResponse') && typeof o[k] === 'object') o[k] = JSON.stringify({ jsonrpc: '2.0', id: 1, ...o[k] });
      else strResponses(o[k]);
    }
  }
};
strResponses(out);

const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, '..', 'vectors_rpc.json'), JSON.stringify(out, null, 1) + '\n');
