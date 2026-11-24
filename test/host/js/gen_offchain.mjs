// Reference vectors for the offchain feature (host tests).
//   - off-chain message signing:  @solana/offchain-messages 8.6.0 (Solana kit), spec version 0
//   - Sign-In With Solana:        @solana/wallet-standard-util 1.2.0
//   - Solana Pay:                 @solana/pay 0.2.6 (web3.js based, installed as solana-pay-classic)
// Run: node gen_offchain.mjs   (writes ../vectors_offchain.json, identical on every run)
import fs from 'fs';
import { createRequire } from 'module';
import bs58 from 'bs58';
import nacl from 'tweetnacl';
import * as om from '@solana/offchain-messages';
import { createKeyPairFromPrivateKeyBytes } from '@solana/keys';
import { getAddressFromPublicKey } from '@solana/addresses';
import * as wsu from '@solana/wallet-standard-util';
import * as pay from 'solana-pay-classic';

// the web3.js / spl-token copies that @solana/pay itself uses, so the classes match
const payRequire = createRequire(new URL(import.meta.resolve('solana-pay-classic')));
const web3 = payRequire('@solana/web3.js');
const spl = payRequire('@solana/spl-token');
const BigNumber = payRequire('bignumber.js');
const { PublicKey, Keypair, Transaction, SystemProgram, TransactionInstruction } = web3;

const pkgVersion = (p) => JSON.parse(fs.readFileSync(new URL(`./node_modules/${p}/package.json`, import.meta.url))).version;

// deterministic PRNG so the vectors are stable
let s = 0x2f6e2b1d;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const hex = (b) => Buffer.from(b).toString('hex');
const pick = (a) => a[rnd() % a.length];
const kp = () => Keypair.fromSeed(bytes(32));
const key = () => kp().publicKey;
const b58 = (b) => bs58.encode(b);

const out = {
  versions: {
    '@solana/offchain-messages': pkgVersion('@solana/offchain-messages'),
    '@solana/wallet-standard-util': pkgVersion('@solana/wallet-standard-util'),
    '@solana/pay': pkgVersion('solana-pay-classic'),
    '@solana/web3.js (pay)': JSON.parse(fs.readFileSync(payRequire.resolve('@solana/web3.js').replace(/lib\/index.cjs.js$/, 'package.json'))).version,
  },
  offchain: {}, siws: {}, pay: {},
};

// ============================================================================
// 1. Off-chain messages (kit)
// ============================================================================
const FORMATS = [om.OffchainMessageContentFormat.RESTRICTED_ASCII_1232_BYTES_MAX, om.OffchainMessageContentFormat.UTF8_1232_BYTES_MAX, om.OffchainMessageContentFormat.UTF8_65535_BYTES_MAX];

// a signer that exists both as web3.js keypair (secret64) and as a CryptoKeyPair
async function signer() {
  const seed = bytes(32);
  const w = Keypair.fromSeed(seed);
  const ck = await createKeyPairFromPrivateKeyBytes(seed);
  const address = await getAddressFromPublicKey(ck.publicKey);
  if (address !== w.publicKey.toBase58()) throw new Error('address mismatch');
  return { secret: hex(w.secretKey), address, ck };
}
const expandText = (c) => (c.repeat !== undefined ? c.fill.repeat(c.repeat) : c.text);
const textJson = (c) => (c.repeat !== undefined ? { fill: c.fill, repeat: c.repeat } : { text: c.text });

function kitMessage(c, signers, domain) {
  return {
    version: 0,
    applicationDomain: domain,
    content: Object.freeze({ format: FORMATS[c.format], text: expandText(c) }),
    requiredSignatories: signers.map((x) => ({ address: x.address })),
  };
}

const signersPool = [];
for (let i = 0; i < 4; i++) signersPool.push(await signer());

const ocCases = [
  { name: 'ascii hello', format: 0, text: 'hello', n: 1 },
  { name: 'ascii sentence two signers', format: 0, text: 'Sign this to log in to Example, nonce 12345.', n: 2 },
  { name: 'ascii all printable', format: 0, text: Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join(''), n: 1 },
  { name: 'utf8 limited turkish', format: 1, text: 'Merhaba dünya, şifre onayı ✓', n: 1 },
  { name: 'utf8 limited emoji + cjk', format: 1, text: '🚀 launch 日本語 テスト', n: 3 },
  { name: 'utf8 limited ascii text', format: 1, text: 'plain ascii in utf8 format', n: 1 },
  { name: 'utf8 extended multi line', format: 2, text: 'line one\nline two\ttabbed\r\nüçğ', n: 2 },
  { name: 'utf8 extended 5000 chars', format: 2, fill: 'é', repeat: 5000, n: 1 },
  { name: 'ascii max 1 signer', format: 0, fill: 'a', repeat: 1147, n: 1 },
  { name: 'utf8 limited max 1 signer', format: 1, fill: 'b', repeat: 1147, n: 1 },
  { name: 'ascii max 3 signers', format: 0, fill: 'c', repeat: 1232 - (53 + 96), n: 3 },
  { name: 'utf8 limited max 2 signers (2-byte chars)', format: 1, fill: 'ü', repeat: Math.floor((1232 - (53 + 64)) / 2), n: 2 },
  { name: 'utf8 extended max', format: 2, fill: 'x', repeat: 65535, n: 1 },
  // must be rejected
  { name: 'ascii max + 1', format: 0, fill: 'a', repeat: 1148, n: 1 },
  { name: 'utf8 limited max + 1', format: 1, fill: 'b', repeat: 1148, n: 1 },
  { name: 'ascii 3 signers max + 1', format: 0, fill: 'c', repeat: 1232 - (53 + 96) + 1, n: 3 },
  { name: 'utf8 extended max + 1', format: 2, fill: 'x', repeat: 65536, n: 1 },
  { name: 'ascii with newline', format: 0, text: 'two\nlines', n: 1 },
  { name: 'ascii with tab', format: 0, text: 'a\tb', n: 1 },
  { name: 'ascii with DEL', format: 0, text: 'a\x7fb', n: 1 },
  { name: 'ascii with non-ascii', format: 0, text: 'café', n: 1 },
  { name: 'empty ascii', format: 0, text: '', n: 1 },
  { name: 'empty utf8', format: 1, text: '', n: 1 },
  { name: 'empty extended', format: 2, text: '', n: 1 },
];

out.offchain.domains = [];
out.offchain.cases = [];
for (const c of ocCases) {
  const domain = b58(bytes(32));
  const signers = signersPool.slice(0, c.n);
  const rec = { name: c.name, format: c.format, ...textJson(c), applicationDomain: domain, signers: signers.map((x) => x.address), secrets: signers.map((x) => x.secret) };
  let env;
  try {
    const msg = kitMessage(c, signers, domain);
    env = om.compileOffchainMessageV0Envelope(msg);
  } catch (e) {
    rec.ok = false;
    out.offchain.cases.push(rec);
    continue;
  }
  rec.ok = true;
  rec.content = hex(env.content);
  // sign with all signers, and also build a partial envelope (first signer missing when there are 2+)
  const full = await om.signOffchainMessageEnvelope(signers.map((x) => x.ck), env);
  const enc = om.getOffchainMessageEnvelopeEncoder();
  rec.signatures = signers.map((x) => hex(full.signatures[x.address]));
  rec.envelope = hex(enc.encode(full));
  await om.verifyOffchainMessageEnvelope(full);
  if (signers.length > 1) {
    const partial = await om.partiallySignOffchainMessageEnvelope(signers.slice(1).map((x) => x.ck), env);
    rec.partialEnvelope = hex(enc.encode(partial));
    rec.partialSigners = signers.slice(1).map((x) => x.address);
  }
  // text fields are huge for the max cases: the content bytes are only stored for small ones
  if (rec.content.length > 4000) { delete rec.content; delete rec.envelope; delete rec.partialEnvelope; rec.contentLength = env.content.length; }
  out.offchain.cases.push(rec);
}

// kit decoder verdicts for mutated content / envelopes
{
  const base = ocCases[4]; // utf8 limited, 3 signers
  const signers = signersPool.slice(0, 3);
  const domain = b58(bytes(32));
  const env = om.compileOffchainMessageV0Envelope(kitMessage(base, signers, domain));
  const c = Uint8Array.from(env.content);
  const mut = [];
  const add = (name, f) => { const b = Uint8Array.from(c); const r = f(b) || b; mut.push({ name, content: hex(r) }); };
  add('unmodified', () => null);
  add('bad signing domain', (b) => { b[0] = 0xfe; });
  add('bad signing domain text', (b) => { b[3] ^= 1; });
  add('version 1', (b) => { b[16] = 1; });
  add('version 255', (b) => { b[16] = 255; });
  add('format 3', (b) => { b[49] = 3; });
  add('zero signers', (b) => { b[50] = 0; });
  add('signer count too large', (b) => { b[50] = 4; });
  add('length field +1', (b) => { const o = 51 + 96; b[o] = (b[o] + 1) & 0xff; });
  add('length field -1', (b) => { const o = 51 + 96; b[o] = (b[o] - 1) & 0xff; });
  add('trailing byte', (b) => { const r = new Uint8Array(b.length + 1); r.set(b); r[b.length] = 0x41; return r; });
  add('truncated body', (b) => b.slice(0, b.length - 3));
  add('truncated preamble', (b) => b.slice(0, 60));
  add('empty', () => new Uint8Array(0));
  add('ascii format with utf8 body', (b) => { b[49] = 0; });
  // invalid UTF-8 inside the body (0xff can never occur), same length
  add('invalid utf8', (b) => { b[b.length - 1] = 0xff; });
  const dec = om.getOffchainMessageV0Decoder();
  for (const m of mut) {
    try { const d = dec.decode(Buffer.from(m.content, 'hex')); m.ok = true; m.text = d.content.text; m.format = d.content.format; m.signers = d.requiredSignatories.map((x) => x.address); }
    catch (e) { m.ok = false; }
  }
  out.offchain.mutations = mut;

  // envelope-level checks (kit envelope decoder + verify)
  const full = await om.signOffchainMessageEnvelope(signers.map((x) => x.ck), env);
  const enc = om.getOffchainMessageEnvelopeEncoder();
  const fullBytes = Uint8Array.from(enc.encode(full));
  const envs = [];
  const addE = (name, f) => { const b = Uint8Array.from(fullBytes); const r = f(b) || b; envs.push({ name, envelope: hex(r) }); };
  addE('valid', () => null);
  addE('flipped signature bit', (b) => { b[1 + 64 + 5] ^= 1; });
  addE('flipped body bit', (b) => { b[b.length - 1] ^= 1; });
  addE('zero signature (missing)', (b) => { b.fill(0, 1 + 64, 1 + 128); });
  addE('signature count 2 of 3', (b) => { const r = new Uint8Array(b.length - 64); r[0] = 2; r.set(b.slice(1, 129), 1); r.set(b.slice(1 + 192), 129); return r; });
  addE('signature count 0', (b) => { const r = new Uint8Array(b.length - 192); r[0] = 0; r.set(b.slice(1 + 192), 1); return r; });
  addE('truncated envelope', (b) => b.slice(0, 100));
  addE('empty', () => new Uint8Array(0));
  addE('swapped signatures', (b) => { const a = b.slice(1, 65), c2 = b.slice(65, 129); b.set(c2, 1); b.set(a, 65); });
  const edec = om.getOffchainMessageEnvelopeDecoder();
  for (const e of envs) {
    try {
      const d = edec.decode(Buffer.from(e.envelope, 'hex'));
      e.decodes = true;
      try { await om.verifyOffchainMessageEnvelope(d); e.verifies = true; } catch { e.verifies = false; }
    } catch { e.decodes = false; e.verifies = false; }
  }
  out.offchain.envelopes = envs;
  out.offchain.envelopeSecrets = signers.map((x) => x.secret);
}

// ============================================================================
// 2. Sign-In With Solana (wallet-standard-util)
// ============================================================================
const textsPool = [
  'Sign in to Example', 'I accept the Terms of Service: https://example.com/tos', 'Üyelik girişi — şifresiz', 'Line one\nLine two',
  'Contains URI: inside text', 'Sign in\nURI: fake\nVersion: 9', '🚀 launch', 'a', 'Statement with trailing space ',
];
const domains = ['example.com', 'app.example.org:8080', 'localhost', 'xn--bcher-kva.example', 'sub.domain.co.uk'];
const siwsInputs = [];
const rndTime = () => { const t = Date.UTC(2025, 0, 1) + (rnd() % 50000000) * 1000; return new Date(t).toISOString(); };
for (let i = 0; i < 40; i++) {
  const w = kp();
  const m = { domain: pick(domains), address: w.publicKey.toBase58() };
  // each optional field present with ~60% probability, the first cases cover all / none
  const on = () => (i === 0 ? true : i === 1 ? false : rnd() % 10 < 6);
  if (on()) m.statement = pick(textsPool);
  if (on()) m.uri = `https://${m.domain}/login?x=${rnd() % 1000}`;
  if (on()) m.version = '1';
  if (on()) m.chainId = pick(['mainnet', 'devnet', 'testnet', 'solana:mainnet']);
  if (on()) m.nonce = b58(bytes(6)).slice(0, 8) + (rnd() % 100000);
  if (on()) m.issuedAt = rndTime();
  if (on()) m.expirationTime = rndTime();
  if (on()) m.notBefore = rndTime();
  if (on()) m.requestId = 'req-' + (rnd() % 100000);
  if (on()) m.resources = Array.from({ length: 1 + (rnd() % 3) }, () => pick(['https://example.com/a', 'ipfs://Qm' + b58(bytes(8)), 'https://example.com/b?c=d']));
  siwsInputs.push({ input: m, secret: w.secretKey });
}
out.siws.cases = [];
for (const { input, secret } of siwsInputs) {
  const text = wsu.createSignInMessageText(input);
  const msgBytes = new TextEncoder().encode(text);
  const sig = nacl.sign.detached(msgBytes, secret);
  const pub = secret.slice(32);
  const output = { account: { address: input.address, publicKey: pub }, signedMessage: msgBytes, signature: sig };
  const parsed = wsu.parseSignInMessageText(text);
  out.siws.cases.push({
    input: { ...input, resources: input.resources },
    secret: hex(secret),
    text,
    signature: hex(sig),
    verifies: wsu.verifySignIn(input, output),
    parsed: parsed ? JSON.parse(JSON.stringify(parsed)) : null,
  });
}
// verification failures: expected input differs / tampered signature / wrong key / non canonical text
out.siws.verify = [];
{
  const w = kp(), other = kp();
  const input = { domain: 'example.com', address: w.publicKey.toBase58(), statement: 'Sign in', uri: 'https://example.com', version: '1', chainId: 'mainnet', nonce: 'abcd1234', issuedAt: '2025-01-01T00:00:00.000Z', expirationTime: '2030-01-01T00:00:00.000Z', notBefore: '2024-01-01T00:00:00.000Z', requestId: 'r1', resources: ['https://example.com/a', 'https://example.com/b'] };
  const text = wsu.createSignInMessageText(input);
  const sign = (t, sk) => nacl.sign.detached(new TextEncoder().encode(t), sk);
  const mk = (name, expected, t, sk, pubKey, sigMut) => {
    const msg = new TextEncoder().encode(t);
    let sig = Uint8Array.from(sign(t, sk));
    if (sigMut) sig[3] ^= 1;
    const pub = pubKey || w.secretKey.slice(32);
    const address = b58(pub);
    const output = { account: { address, publicKey: pub }, signedMessage: msg, signature: sig };
    out.siws.verify.push({ name, expected, text: t, signature: hex(sig), publicKey: hex(pub), expectOk: wsu.verifySignIn(expected, output) });
  };
  mk('exact', input, text, w.secretKey);
  mk('expected without domain and address', { ...input, domain: undefined, address: undefined }, text, w.secretKey);
  mk('wrong domain', { ...input, domain: 'evil.com' }, text, w.secretKey);
  mk('wrong address expected', { ...input, address: other.publicKey.toBase58() }, text, w.secretKey);
  mk('wrong nonce', { ...input, nonce: 'zzzz9999' }, text, w.secretKey);
  mk('missing statement in expected', { ...input, statement: undefined }, text, w.secretKey);
  mk('resources differ', { ...input, resources: ['https://example.com/a'] }, text, w.secretKey);
  mk('resources missing in expected', { ...input, resources: undefined }, text, w.secretKey);
  mk('flipped signature', input, text, w.secretKey, null, true);
  mk('signed by other key', input, text, other.secretKey);
  mk('public key does not match address text', input, wsu.createSignInMessageText({ ...input, address: other.publicKey.toBase58() }), other.secretKey, w.secretKey.slice(32));
  mk('trailing newline (non canonical)', input, text + '\n', w.secretKey);
  mk('extra blank line (non canonical)', input, text.replace('\n\nURI', '\n\n\nURI'), w.secretKey);
  mk('not a siws text', input, 'hello world', w.secretKey);
}
// parse behaviour of the reference regex on tricky and random texts (null = does not parse)
out.siws.parse = [];
{
  const addr = key().toBase58();
  const head = 'example.com wants you to sign in with your Solana account:\n' + addr;
  const hand = [
    head, head + '\n', head + '\n\n', head + '\n\nStatement', head + '\n\nStatement\n', head + '\n\nStatement\n\n',
    head + '\n\nURI: https://x', head + '\n\nURI: https://x\n\n', head + '\n\nURI: https://x\nVersion: 1',
    head + '\n\nStmt\n\nURI: https://x\nVersion: 1\nChain ID: m\nNonce: n1\nIssued At: t\nExpiration Time: e\nNot Before: b\nRequest ID: r\nResources:\n- a\n- b',
    head + '\n\nResources:', head + '\n\nResources:\n- a', head + '\n\nResources:\n- ', head + '\n\nVersion: 1\nURI: https://x',
    head + '\nURI: https://x', head + '\n\n\nURI: https://x', head + '\n\nSign in\nURI: fake\n\nURI: real',
    head + '\n\nSign in\nURI: fake', head + '\n\nline1\nline2\n\nNonce: abc', head + '\n\nURI: ', head + '\n\nURI:  x',
    'example.com wants you to sign in with your Solana account:\n', 'example.com wants you to sign in with your Solana account:',
    ' wants you to sign in with your Solana account:\n' + addr, 'a wants you to sign in with your Solana account:\n' + addr,
    'example.com wants you to sign in with your Ethereum account:\n' + addr, 'x wants you to sign in with your Solana account:\n' + addr + '\n\nS\n\n\n\n',
    head + '\n\nStatement: with colon\n\nChain ID: devnet', head + '\n\nUnknown: field', head + '\n\nURI: a\nURI: b',
    'example.com wants you to sign in with your Solana account: wants you to sign in with your Solana account:\n' + addr,
  ];
  const labels = ['URI: u', 'Version: 1', 'Chain ID: c', 'Nonce: n', 'Issued At: i', 'Expiration Time: e', 'Not Before: b', 'Request ID: r', 'Resources:', '- res'];
  const pieces = ['Statement', 'Two\nLines', '', 'URI: sneaky', '\n', 'Resources:', '- x'];
  const fuzz = [];
  for (let i = 0; i < 120; i++) {
    let t = head;
    const n = rnd() % 6;
    for (let j = 0; j < n; j++) t += pick(['\n', '\n\n', '\n', '']) + (rnd() % 3 ? pick(labels) : pick(pieces));
    if (rnd() % 4 === 0) t += pick(['\n', '\n\n', ' ']);
    fuzz.push(t);
  }
  for (const t of hand.concat(fuzz)) {
    const p = wsu.parseSignInMessageText(t);
    out.siws.parse.push({ text: t, parsed: p ? JSON.parse(JSON.stringify(p)) : null });
  }
}

// ============================================================================
// 3. Solana Pay
// ============================================================================
const fieldsJson = (f) => ({
  recipient: f.recipient.toBase58(),
  amount: f.amount === undefined ? undefined : f.amount.toFixed(),
  splToken: f.splToken ? f.splToken.toBase58() : undefined,
  reference: f.reference ? (Array.isArray(f.reference) ? f.reference : [f.reference]).map((r) => r.toBase58()) : undefined,
  label: f.label, message: f.message, memo: f.memo,
});

// ---- URL encoding / parsing ----
out.pay.transfers = [];
const amounts = [undefined, '1', '0', '0.5', '001.2300', '12345678.123456789', '1.0', '100', '0.000000001', '7.25', '99999999999999999999.99'];
const nasty = ['hello', 'Coffee & cake = 5', 'a+b c%d', '100% sure #1', 'ünïcödé ✓ 🚀', "it's (ok) ~!*", 'line1\nline2', 'path/with/slash?and=query', 'x'.repeat(100), '%2F encoded', '"quoted"', 'tab\there', 'ç ğ ı ö ş ü'];
for (let i = 0; i < 48; i++) {
  const f = { recipient: key() };
  const a = amounts[i % amounts.length];
  if (a !== undefined) f.amount = new BigNumber(a);
  if (rnd() % 3 === 0) f.splToken = key();
  const nref = rnd() % 4;
  if (nref) f.reference = nref === 1 && rnd() % 2 ? key() : Array.from({ length: nref }, () => key());
  if (rnd() % 2) f.label = pick(nasty);
  if (rnd() % 2) f.message = pick(nasty);
  if (rnd() % 3 === 0) f.memo = pick(nasty);
  const url = pay.encodeURL(f).toString();
  const parsed = fieldsJson(pay.parseURL(url));
  out.pay.transfers.push({
    request: { ...fieldsJson(f), amountInput: a },
    url,
    parsed,
  });
}
// transaction requests
out.pay.txRequests = [];
const links = [
  'https://example.com/api', 'https://example.com/api/', 'https://example.com', 'https://example.com/', 'https://example.com/api?id=1&x=y',
  'https://example.com/?a=b', 'https://EXAMPLE.com:443/Path/To', 'https://example.com:8443/pay?ref=a%20b', 'https://sub.example.com/a/b/c?x=1&y=%26',
  'https://example.com/api?', 'https://example.com/ü',
];
for (const l of links) for (const [label, message] of [[undefined, undefined], ['Shop', 'Thanks & bye']]) {
  const url = pay.encodeURL({ link: new URL(l), label, message }).toString();
  const p = pay.parseURL(url);
  out.pay.txRequests.push({ link: new URL(l).href, label, message, url, parsedLink: p.link.href, parsedLabel: p.label, parsedMessage: p.message });
}
// parse-only inputs (including invalid ones)
out.pay.parse = [];
{
  const r = key().toBase58(), t = key().toBase58(), ref = key().toBase58();
  const raw = [
    `solana:${r}`, `solana:${r}?amount=1.5`, `solana:${r}?amount=001.50&label=a%20b&message=x+y&memo=m%26m`, `SOLANA:${r}?amount=2`, `Solana:${r}`,
    `solana:${r}?amount=1&spl-token=${t}&reference=${ref}&reference=${t}`, `solana:${r}?amount=1&amount=2`, `solana:${r}?label=&message=&memo=`,
    `solana:${r}?label=a+b%20c&label=second`, `solana:${r}?label=%E2%9C%93%F0%9F%9A%80`, `solana:${r}?label=bad%ZZpercent`, `solana:${r}?label=%FF`, `solana:${r}#frag`, `solana:${r}?amount=1#frag`,
    `  solana:${r}?amount=3  `, `solana:${r}?amount=1&&amount2=3&`, `solana:${r}?=novalue&amount=4`, `solana:${r}?amount`,
    // invalid
    `solana:`, `solana:?amount=1`, `solana:short`, `solana:${r}0`, `solana:${r}?amount=-1`, `solana:${r}?amount=1e3`, `solana:${r}?amount=.5`, `solana:${r}?amount=1.`, `solana:${r}?amount=1,5`, `solana:${r}?amount=`,
    `solana:${r}?amount=abc`, `solana:${r}?amount=%2B1`, `solana:${r}?spl-token=nope`, `solana:${r}?reference=nope`, `solana:${r}?amount=1&reference=${ref}&reference=bad`,
    `bitcoin:${r}`, `https://${r}`, `${r}`, '', 'solana', `solana:${r}?memo=${'a'.repeat(2100)}`,
    // transaction requests
    'solana:https://example.com/api', 'solana:https%3A%2F%2Fexample.com%2Fapi%3Fx%3D1?label=q&message=hi', 'solana:https://example.com/api?label=Shop',
    'solana:http%3A%2F%2Fexample.com%2Fapi', 'solana:http://example.com/api', 'solana:https%3A%2F%2F', 'solana:https%3A%2F%2Fexample.com%2F%ZZ', 'solana:https%3A%2F%2Fexample.com',
    'solana:ftp%3A%2F%2Fexample.com', 'solana:javascript%3Aalert(1)', 'solana:https%3A%2F%2Fuser%40example.com%2Fapi',
  ];
  for (const u of raw) {
    try {
      const p = pay.parseURL(u);
      if (p.link) out.pay.parse.push({ url: u, ok: true, kind: 'tx', link: p.link.href, label: p.label, message: p.message });
      else out.pay.parse.push({ url: u, ok: true, kind: 'transfer', ...fieldsJson(p) });
    } catch (e) {
      out.pay.parse.push({ url: u, ok: false, errorName: e.name, error: e.name === 'ParseURLError' ? e.message : undefined });
    }
  }
}
// amount conversion (BigNumber floor, as in createTransfer)
out.pay.amounts = [];
for (const [a, d] of [['1', 9], ['0.5', 9], ['1.5', 6], ['0.000001', 6], ['0.0000001', 6], ['123456.789', 3], ['18446744073.709551615', 9], ['18446744073.709551616', 9], ['0', 6], ['10.10', 1], ['10.11', 1], ['5', 0], ['5.1', 0], ['18446744073709551615', 0], ['18446744073709551616', 0]]) {
  const bn = new BigNumber(a);
  const exact = (bn.decimalPlaces() ?? 0) <= d;
  const units = bn.times(new BigNumber(10).pow(d)).integerValue(BigNumber.ROUND_FLOOR);
  const ceil = bn.times(new BigNumber(10).pow(d)).integerValue(BigNumber.ROUND_CEIL);
  const fits = (x) => x.lte(new BigNumber('18446744073709551615'));
  out.pay.amounts.push({ amount: a, decimals: d, exact, floor: units.toFixed(), floorFits: fits(units), ceil: ceil.toFixed(), ceilFits: fits(ceil) });
}

// ---- the world: accounts for createTransfer / validateTransfer ----
const BLOCKHASH = b58(bytes(32));
const sender = kp(), recipient = kp();
const mint = key(), mint2022 = key();
const r1 = key(), r2 = key(), r3 = key();
const SYS = SystemProgram.programId;

const mintData = (decimals, init = 1) => {
  const b = Buffer.alloc(spl.MINT_SIZE);
  spl.MintLayout.encode({ mintAuthorityOption: 1, mintAuthority: key(), supply: 1000000000000n, decimals, isInitialized: !!init, freezeAuthorityOption: 0, freezeAuthority: PublicKey.default }, b);
  return b;
};
const tokenData = (mintKey, owner, amount, state = 1) => {
  const b = Buffer.alloc(spl.ACCOUNT_SIZE);
  spl.AccountLayout.encode({ mint: mintKey, owner, amount: BigInt(amount), delegateOption: 0, delegate: PublicKey.default, delegatedAmount: 0n, state, isNativeOption: 0, isNative: 0n, delegatedAmount2: 0n, closeAuthorityOption: 0, closeAuthority: PublicKey.default }, b);
  return b;
};
const ata = (m, o, prog = spl.TOKEN_PROGRAM_ID) => spl.getAssociatedTokenAddressSync(m, o, false, prog);

class FakeConn {
  constructor(accounts) { this.accounts = accounts; }
  async getAccountInfo(pk) {
    const a = this.accounts[pk.toBase58()];
    return a ? { data: a.data || Buffer.alloc(0), owner: a.owner, lamports: a.lamports, executable: !!a.executable, rentEpoch: 0 } : null;
  }
  async getParsedAccountInfo(pk) { const a = this.accounts[pk.toBase58()]; return { context: { slot: 1 }, value: a ? { owner: a.owner, lamports: a.lamports, data: a.data, executable: false } : null }; }
  async getLatestBlockhash() { return { blockhash: BLOCKHASH, lastValidBlockHeight: 100 }; }
}
const sysAcc = (lamports) => ({ owner: SYS, lamports });
const accJson = (accounts) => Object.fromEntries(Object.entries(accounts).map(([k, a]) => [k, { owner: a.owner.toBase58(), lamports: a.lamports, executable: !!a.executable, data: a.data ? a.data.toString('base64') : '' }]));

const baseAccounts = () => ({
  [sender.publicKey.toBase58()]: sysAcc(5_000_000_000),
  [recipient.publicKey.toBase58()]: sysAcc(1_000_000),
  [mint.toBase58()]: { owner: spl.TOKEN_PROGRAM_ID, lamports: 1461600, data: mintData(6) },
  [ata(mint, sender.publicKey).toBase58()]: { owner: spl.TOKEN_PROGRAM_ID, lamports: 2039280, data: tokenData(mint, sender.publicKey, 10_000_000) },
  [ata(mint, recipient.publicKey).toBase58()]: { owner: spl.TOKEN_PROGRAM_ID, lamports: 2039280, data: tokenData(mint, recipient.publicKey, 500) },
});
const msgHex = (tx) => hex(tx.compileMessage().serialize());

out.pay.build = [];
{
  const A = baseAccounts();
  const cases = [
    { name: 'sol, memo and two references', fields: { recipient: recipient.publicKey, amount: new BigNumber('1.5'), reference: [r1, r2], memo: 'order-42' } },
    { name: 'sol, no memo no reference', fields: { recipient: recipient.publicKey, amount: new BigNumber('0.000000001') } },
    { name: 'sol, single reference', fields: { recipient: recipient.publicKey, amount: new BigNumber('2'), reference: r3 } },
    { name: 'sol, unicode memo', fields: { recipient: recipient.publicKey, amount: new BigNumber('1'), memo: 'kahve ☕ #7' } },
    { name: 'spl, memo and references', fields: { recipient: recipient.publicKey, amount: new BigNumber('2.5'), splToken: mint, reference: [r1, r2], memo: 'inv-9' } },
    { name: 'spl, plain', fields: { recipient: recipient.publicKey, amount: new BigNumber('0.000001'), splToken: mint } },
    // failures
    { name: 'sol, insufficient funds', fields: { recipient: recipient.publicKey, amount: new BigNumber('6') } },
    { name: 'sol, too many decimals', fields: { recipient: recipient.publicKey, amount: new BigNumber('0.0000000001') } },
    { name: 'sol, recipient not found', fields: { recipient: key(), amount: new BigNumber('1') } },
    { name: 'sol, recipient owned by a program', fields: { recipient: recipient.publicKey, amount: new BigNumber('1') }, tweak: (a) => { a[recipient.publicKey.toBase58()] = { owner: spl.TOKEN_PROGRAM_ID, lamports: 1 }; } },
    { name: 'sol, recipient executable', fields: { recipient: recipient.publicKey, amount: new BigNumber('1') }, tweak: (a) => { a[recipient.publicKey.toBase58()] = { owner: SYS, lamports: 1, executable: true }; } },
    { name: 'sol, sender not found', fields: { recipient: recipient.publicKey, amount: new BigNumber('1') }, tweak: (a) => { delete a[sender.publicKey.toBase58()]; } },
    { name: 'spl, insufficient funds', fields: { recipient: recipient.publicKey, amount: new BigNumber('11'), splToken: mint } },
    { name: 'spl, too many decimals', fields: { recipient: recipient.publicKey, amount: new BigNumber('1.0000001'), splToken: mint } },
    { name: 'spl, sender frozen', fields: { recipient: recipient.publicKey, amount: new BigNumber('1'), splToken: mint }, tweak: (a) => { a[ata(mint, sender.publicKey).toBase58()].data = tokenData(mint, sender.publicKey, 10_000_000, 2); } },
    { name: 'spl, recipient frozen', fields: { recipient: recipient.publicKey, amount: new BigNumber('1'), splToken: mint }, tweak: (a) => { a[ata(mint, recipient.publicKey).toBase58()].data = tokenData(mint, recipient.publicKey, 500, 2); } },
    { name: 'spl, recipient token account missing', fields: { recipient: recipient.publicKey, amount: new BigNumber('1'), splToken: mint }, tweak: (a) => { delete a[ata(mint, recipient.publicKey).toBase58()]; } },
    { name: 'spl, mint not initialized', fields: { recipient: recipient.publicKey, amount: new BigNumber('1'), splToken: mint }, tweak: (a) => { a[mint.toBase58()].data = mintData(6, 0); } },
  ];
  for (const c of cases) {
    const accounts = baseAccounts();
    if (c.tweak) c.tweak(accounts);
    const rec = { name: c.name, sender: sender.publicKey.toBase58(), blockhash: BLOCKHASH, accounts: accJson(accounts), request: fieldsJson(c.fields) };
    try {
      const tx = await pay.createTransfer(new FakeConn(accounts), sender.publicKey, c.fields);
      rec.ok = true;
      rec.message = msgHex(tx);
    } catch (e) {
      rec.ok = false;
      rec.errorName = e.name;
      rec.error = e instanceof pay.CreateTransferError ? e.message : undefined;
    }
    out.pay.build.push(rec);
  }
  // Token-2022 (@solana/pay 0.2.6 cannot build this: it never recognises a Token-2022 mint), reference built
  // with spl-token's own instruction builder: transferChecked + reference key
  {
    const t22 = spl.TOKEN_2022_PROGRAM_ID;
    const accounts = baseAccounts();
    accounts[mint2022.toBase58()] = { owner: t22, lamports: 1, data: mintData(9) };
    accounts[ata(mint2022, sender.publicKey, t22).toBase58()] = { owner: t22, lamports: 1, data: tokenData(mint2022, sender.publicKey, 9_000_000_000) };
    accounts[ata(mint2022, recipient.publicKey, t22).toBase58()] = { owner: t22, lamports: 1, data: tokenData(mint2022, recipient.publicKey, 0) };
    const ix = spl.createTransferCheckedInstruction(ata(mint2022, sender.publicKey, t22), mint2022, ata(mint2022, recipient.publicKey, t22), sender.publicKey, 1_500_000_000n, 9, [], t22);
    ix.keys.push({ pubkey: r1, isSigner: false, isWritable: false });
    const tx = new Transaction();
    tx.feePayer = sender.publicKey; tx.recentBlockhash = BLOCKHASH;
    tx.add(new TransactionInstruction({ programId: pay.MEMO_PROGRAM_ID, keys: [], data: Buffer.from('t22', 'utf8') }));
    tx.add(ix);
    out.pay.build.push({
      name: 'token-2022 (spl-token instruction builder, not @solana/pay)', sender: sender.publicKey.toBase58(), blockhash: BLOCKHASH, accounts: accJson(accounts),
      request: fieldsJson({ recipient: recipient.publicKey, amount: new BigNumber('1.5'), splToken: mint2022, reference: [r1], memo: 't22' }), ok: true, message: msgHex(tx), referenceImplementation: 'spl-token',
    });
  }
}

// ---- validateTransfer ----
out.pay.validate = [];
{
  const mkSig = () => b58(bytes(64));
  const keysOf = (tx) => tx.compileMessage().accountKeys;
  const rpcOf = (tx, meta, extra) => {
    const msg = tx.compileMessage();
    return {
      slot: 1000, blockTime: 1700000000, version: 'legacy',
      transaction: {
        message: {
          header: msg.header, accountKeys: msg.accountKeys.map((k) => k.toBase58()), recentBlockhash: msg.recentBlockhash,
          instructions: msg.instructions.map((i) => ({ programIdIndex: i.programIdIndex, accounts: i.accounts, data: i.data })),
        },
        signatures: [mkSig()],
      },
      meta: { fee: 5000, computeUnitsConsumed: 450, logMessages: ['Program 11111111111111111111111111111111 invoke [1]', 'Program 11111111111111111111111111111111 success'], rewards: [], status: { Ok: null }, ...meta },
    };
  };
  const solTx = async (fields) => pay.createTransfer(new FakeConn(baseAccounts()), sender.publicKey, fields);
  const splTx = solTx;
  const fullFields = { recipient: recipient.publicKey, amount: new BigNumber('1.5'), reference: [r1, r2], memo: 'order-42' };
  const lam = 1_500_000_000;

  const balMeta = (tx, delta, recipientKey = recipient.publicKey) => {
    const keys = keysOf(tx);
    const idx = keys.findIndex((k) => k.equals(recipientKey));
    const pre = keys.map(() => 2_000_000_000), post = pre.slice();
    pre[idx] = 1_000_000; post[idx] = 1_000_000 + delta;
    return { err: null, preBalances: pre, postBalances: post, preTokenBalances: [], postTokenBalances: [] };
  };
  const tokBal = (idx, amount, decimals) => ({ accountIndex: idx, mint: mint.toBase58(), owner: recipient.publicKey.toBase58(), uiTokenAmount: { amount: String(amount), decimals, uiAmount: Number(amount) / 10 ** decimals, uiAmountString: new BigNumber(amount).div(new BigNumber(10).pow(decimals)).toFixed() } });
  const tokMeta = (tx, delta, pre = 500, mintKey = mint) => {
    const keys = keysOf(tx);
    const idx = keys.findIndex((k) => k.equals(ata(mintKey, recipient.publicKey)));
    const n = keys.length;
    return { err: null, preBalances: Array(n).fill(1), postBalances: Array(n).fill(1), preTokenBalances: [tokBal(idx, pre, 6)], postTokenBalances: [tokBal(idx, pre + delta, 6)] };
  };

  // fake connection that serves one stored getTransaction answer, in the object shape web3.js produces
  const runPay = async (rpc, fields) => {
    let response = null;
    if (rpc) {
      const m = rpc.transaction.message;
      const message = new web3.Message({ header: m.header, accountKeys: m.accountKeys, recentBlockhash: m.recentBlockhash, instructions: m.instructions });
      response = { slot: rpc.slot, transaction: { message, signatures: rpc.transaction.signatures }, meta: rpc.meta };
      if (rpc.noMeta) response.meta = null;
    }
    const conn = { getTransaction: async () => response };
    try { await pay.validateTransfer(conn, 'sig', fields); return { ok: true }; }
    catch (e) { return { ok: false, errorName: e.constructor?.name, error: e instanceof pay.ValidateTransferError ? e.message : undefined }; }
  };
  const add = async (name, rpc, expected, extra = {}) => {
    const res = await runPay(rpc, expected);
    let text = null;
    if (rpc !== null) { const c = { ...rpc }; if (c.noMeta) { delete c.noMeta; delete c.meta; } text = JSON.stringify(c); }
    out.pay.validate.push({ name, rpc: text, expected: fieldsJson(expected), ...res, ...extra });
  };

  const sol = await solTx(fullFields);
  const rpcSol = (delta = lam) => rpcOf(sol, balMeta(sol, delta));
  await add('sol ok exact', rpcSol(), fullFields);
  await add('sol ok overpaid', rpcSol(lam + 1), fullFields);
  await add('sol ok no expected references', rpcSol(), { recipient: recipient.publicKey, amount: new BigNumber('1.5') });
  await add('sol ok no expected memo', rpcSol(), { ...fullFields, memo: undefined });
  await add('sol ok amount with trailing zero decimals', rpcSol(), { ...fullFields, amount: new BigNumber('1.500000000') });
  await add('sol amount too low', rpcSol(lam - 1), fullFields);
  await add('sol expected amount higher', rpcSol(), { ...fullFields, amount: new BigNumber('2') });
  await add('sol recipient balance decreased', rpcSol(-5), fullFields);
  await add('sol wrong recipient', rpcSol(), { ...fullFields, recipient: key() });
  await add('sol wrong second reference', rpcSol(), { ...fullFields, reference: [r1, r3] });
  await add('sol references in other order', rpcSol(), { ...fullFields, reference: [r2, r1] });
  await add('sol too few expected references', rpcSol(), { ...fullFields, reference: [r1] });
  await add('sol too many expected references', rpcSol(), { ...fullFields, reference: [r1, r2, r3] });
  await add('sol wrong memo', rpcSol(), { ...fullFields, memo: 'order-43' });
  await add('sol expected memo is a prefix', rpcSol(), { ...fullFields, memo: 'order-4' });
  await add('sol failed transaction', rpcOf(sol, { ...balMeta(sol, lam), err: { InstructionError: [1, { Custom: 1 }] } }), fullFields);
  await add('sol transaction not found', null, fullFields);
  await add('sol meta missing', { ...rpcSol(), noMeta: true }, fullFields);
  {
    const noMemo = await solTx({ recipient: recipient.publicKey, amount: new BigNumber('1.5'), reference: [r1, r2] });
    await add('sol memo expected but tx has none', rpcOf(noMemo, balMeta(noMemo, lam)), fullFields);
    await add('sol ok without memo', rpcOf(noMemo, balMeta(noMemo, lam)), { ...fullFields, memo: undefined });
    const plain = await solTx({ recipient: recipient.publicKey, amount: new BigNumber('1.5') });
    await add('sol references expected but tx has none', rpcOf(plain, balMeta(plain, lam)), { recipient: recipient.publicKey, amount: new BigNumber('1.5'), reference: [r1] });
    await add('sol ok plain transfer', rpcOf(plain, balMeta(plain, lam)), { recipient: recipient.publicKey, amount: new BigNumber('1.5') });
  }
  {
    // last instruction is not a transfer (memo only) while references are expected
    const memoOnly = new Transaction();
    memoOnly.feePayer = sender.publicKey; memoOnly.recentBlockhash = BLOCKHASH;
    memoOnly.add(new TransactionInstruction({ programId: pay.MEMO_PROGRAM_ID, keys: [{ pubkey: recipient.publicKey, isSigner: false, isWritable: true }], data: Buffer.from('x') }));
    await add('sol last instruction is not a system transfer', rpcOf(memoOnly, balMeta(memoOnly, lam)), { recipient: recipient.publicKey, amount: new BigNumber('1.5'), reference: [r1] });
    // a token transfer is not a system transfer either
    const tokenTx = await splTx({ recipient: recipient.publicKey, amount: new BigNumber('1'), splToken: mint, reference: [r1] });
    await add('sol expected but tx is a token transfer', rpcOf(tokenTx, balMeta(tokenTx, lam)), { recipient: recipient.publicKey, amount: new BigNumber('1'), reference: [r1] });
  }
  // SPL
  const splFields = { recipient: recipient.publicKey, amount: new BigNumber('2.5'), splToken: mint, reference: [r1], memo: 'inv-9' };
  const spt = await splTx(splFields);
  const rpcSpl = (delta = 2_500_000, pre = 500) => rpcOf(spt, tokMeta(spt, delta, pre));
  await add('spl ok exact', rpcSpl(), splFields);
  await add('spl ok overpaid', rpcSpl(2_500_001), splFields);
  await add('spl ok no references expected', rpcSpl(), { ...splFields, reference: undefined, memo: undefined });
  await add('spl ok expected has fewer decimals than sent', rpcSpl(2_500_001), { ...splFields, amount: new BigNumber('2.500000') });
  await add('spl ok expected has more decimals (rounds below sent)', rpcSpl(), { ...splFields, amount: new BigNumber('2.4999999') });
  await add('spl expected has more decimals (above sent)', rpcSpl(), { ...splFields, amount: new BigNumber('2.5000001') });
  await add('spl amount too low', rpcSpl(2_499_999), splFields);
  await add('spl pre balance zero', rpcOf(spt, { ...tokMeta(spt, 2_500_000, 0), preTokenBalances: [] }), splFields);
  await add('spl post balance missing', rpcOf(spt, { ...tokMeta(spt, 2_500_000), postTokenBalances: [] }), splFields);
  await add('spl wrong recipient', rpcSpl(), { ...splFields, recipient: key() });
  await add('spl wrong mint', rpcSpl(), { ...splFields, splToken: key() });
  await add('spl wrong reference', rpcSpl(), { ...splFields, reference: [r2] });
  await add('spl wrong memo', rpcSpl(), { ...splFields, memo: 'inv-10' });
  await add('spl failed transaction', rpcOf(spt, { ...tokMeta(spt, 2_500_000), err: { InstructionError: [1, 'InsufficientFunds'] } }), splFields);
  await add('spl expected spl but tx is sol transfer', rpcOf(sol, balMeta(sol, lam)), { ...splFields, reference: [r1, r2] });
  {
    // plain spl Transfer (instruction 3) with a reference, built with spl-token
    const ix = spl.createTransferInstruction(ata(mint, sender.publicKey), ata(mint, recipient.publicKey), sender.publicKey, 2_500_000n);
    ix.keys.push({ pubkey: r1, isSigner: false, isWritable: false });
    const tx = new Transaction(); tx.feePayer = sender.publicKey; tx.recentBlockhash = BLOCKHASH; tx.add(ix);
    await add('spl ok plain Transfer instruction', rpcOf(tx, tokMeta(tx, 2_500_000)), { recipient: recipient.publicKey, amount: new BigNumber('2.5'), splToken: mint, reference: [r1] });
    await add('spl plain Transfer, wrong reference', rpcOf(tx, tokMeta(tx, 2_500_000)), { recipient: recipient.publicKey, amount: new BigNumber('2.5'), splToken: mint, reference: [r2] });
  }
  {
    // Token-2022 transfer: @solana/pay 0.2.6 looks for the legacy ATA, so the reference result is a failure;
    // the library accepts it (expectedOk is the library's intended behaviour, checked by hand)
    const t22 = spl.TOKEN_2022_PROGRAM_ID;
    const ix = spl.createTransferCheckedInstruction(ata(mint2022, sender.publicKey, t22), mint2022, ata(mint2022, recipient.publicKey, t22), sender.publicKey, 3_000_000_000n, 9, [], t22);
    ix.keys.push({ pubkey: r1, isSigner: false, isWritable: false });
    const tx = new Transaction(); tx.feePayer = sender.publicKey; tx.recentBlockhash = BLOCKHASH; tx.add(ix);
    const keys = keysOf(tx);
    const idx = keys.findIndex((k) => k.equals(ata(mint2022, recipient.publicKey, t22)));
    const tb = (amount) => ({ accountIndex: idx, mint: mint2022.toBase58(), owner: recipient.publicKey.toBase58(), uiTokenAmount: { amount: String(amount), decimals: 9, uiAmount: Number(amount) / 1e9, uiAmountString: new BigNumber(amount).div(1e9).toFixed() } });
    const meta = { err: null, preBalances: Array(keys.length).fill(1), postBalances: Array(keys.length).fill(1), preTokenBalances: [tb(0)], postTokenBalances: [tb(3_000_000_000)] };
    const exp = { recipient: recipient.publicKey, amount: new BigNumber('3'), splToken: mint2022, reference: [r1] };
    const res = await runPay(rpcOf(tx, meta), exp);
    out.pay.validate.push({ name: 'token-2022 transferChecked', rpc: JSON.stringify(rpcOf(tx, meta)), expected: fieldsJson(exp), payReferenceOk: res.ok, ok: true, extension: true });
  }
  {
    // versioned transaction: the recipient comes from a lookup table (meta.loadedAddresses)
    const rpc = rpcSol();
    const msg = rpc.transaction.message;
    const ridx = msg.accountKeys.indexOf(recipient.publicKey.toBase58());
    // move the recipient key (and the unused references) behind the static keys; indexes of the static part are unchanged
    const keep = msg.accountKeys.length - 1;
    const loaded = [recipient.publicKey.toBase58()];
    const stat = msg.accountKeys.filter((k) => k !== recipient.publicKey.toBase58());
    const remap = (i) => (i === ridx ? stat.length : i > ridx ? i - 1 : i);
    const rpc2 = JSON.parse(JSON.stringify(rpc));
    rpc2.version = 0;
    rpc2.transaction.message.accountKeys = stat;
    rpc2.transaction.message.instructions = msg.instructions.map((i) => ({ ...i, programIdIndex: remap(i.programIdIndex), accounts: i.accounts.map(remap) }));
    rpc2.meta.loadedAddresses = { writable: loaded, readonly: [] };
    const pre = rpc.meta.preBalances.slice(), post = rpc.meta.postBalances.slice();
    const pre2 = pre.filter((_, i) => i !== ridx).concat([pre[ridx]]), post2 = post.filter((_, i) => i !== ridx).concat([post[ridx]]);
    rpc2.meta.preBalances = pre2; rpc2.meta.postBalances = post2;
    void keep;
    out.pay.validate.push({ name: 'sol ok recipient loaded from lookup table', rpc: JSON.stringify(rpc2), expected: fieldsJson(fullFields), ok: true, extension: true });
  }
}

// ---- findReference ----
out.pay.findReference = [];
for (const n of [0, 1, 7, 99, 100, 101, 250]) {
  const chain = Array.from({ length: n }, () => b58(bytes(64))); // newest first
  const ref = key();
  const conn = {
    getSignaturesForAddress: async (r, opts) => {
      let list = chain;
      if (opts?.before) list = chain.slice(chain.indexOf(opts.before) + 1);
      const limit = opts?.limit ?? 1000;
      return list.slice(0, limit).map((signature) => ({ signature, slot: 1, err: null }));
    },
  };
  let oldest = null;
  try { oldest = (await pay.findReference(conn, ref)).signature; } catch (e) { oldest = null; }
  out.pay.findReference.push({ count: n, reference: ref.toBase58(), chain, oldest });
}

// kept stable across runs: stringify with sorted-free insertion order, 1 space indent for review diffs
fs.writeFileSync(new URL('../vectors_offchain.json', import.meta.url), JSON.stringify(out));
console.error(`wrote vectors_offchain.json: ${out.offchain.cases.length} offchain, ${out.siws.cases.length}+${out.siws.parse.length} siws, ${out.pay.transfers.length}+${out.pay.parse.length} pay urls, ${out.pay.validate.length} validate`);
