// FallForge Mint — the minting pipeline's pure core. Layer 2 of the sovereign-node factory:
// a limb model writes a SPEC (system prompt + few-shot exemplars), this kernel assembles it
// deterministically into a Modelfile, the minted node is gated by fallforge-gate against its
// own raw base, and the whole mint is sealed into a signable manifest. v1 mints PROMPT-TUNED
// nodes (Modelfile-level — owned, private, reproducible); weight-level LoRA is v2 and lands
// in these same stages. A node is MINTED only on a certified BEATS receipt — the pipeline
// cannot declare success, it can only measure it.
// No I/O here. Pure and total: garbage in → { ok:false, why }, never a throw.

export const MAX_SYSTEM = 4000;      // a spec is a distillation, not a dataset dump
export const MAX_FEWSHOT = 8;
export const MAX_MSG = 2000;
export const MAX_ROUNDS = 5;         // refinement is bounded — a mint that needs more is a bad spec
export const TEMP_MIN = 0, TEMP_MAX = 1;
export const PREDICT_MIN = 16, PREDICT_MAX = 1024;

const isStr = (v) => typeof v === 'string';
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const isInt = (v) => Number.isInteger(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const HEX = /^[0-9a-f]+$/;

// ── SHA-256 + canonical JSON (the same proven pair the gate runs on) ────────────────────────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── the spec: what the limb writes, bounded and clean ───────────────────────────────────────────
const FENCE = '"""';

export function validSpec(spec) {
  if (!isObj(spec)) return { ok: false, why: 'a spec is an object' };
  if (!isStr(spec.system) || spec.system.trim().length === 0) return { ok: false, why: 'a spec needs a non-empty system prompt' };
  if (spec.system.length > MAX_SYSTEM) return { ok: false, why: 'system prompt exceeds ' + MAX_SYSTEM + ' characters — a spec is a distillation, not a dump' };
  if (spec.system.includes(FENCE)) return { ok: false, why: 'system prompt may not contain a triple-quote fence' };
  if (!Array.isArray(spec.fewshot)) return { ok: false, why: 'fewshot must be an array (it may be empty)' };
  if (spec.fewshot.length > MAX_FEWSHOT) return { ok: false, why: 'more than ' + MAX_FEWSHOT + ' few-shot exemplars — trim the spec' };
  for (const [i, m] of spec.fewshot.entries()) {
    if (!isObj(m) || !isStr(m.user) || !isStr(m.assistant)) return { ok: false, why: 'fewshot ' + i + ' must be { user, assistant } strings' };
    if (m.user.trim().length === 0 || m.assistant.trim().length === 0) return { ok: false, why: 'fewshot ' + i + ' has an empty side' };
    if (m.user.length > MAX_MSG || m.assistant.length > MAX_MSG) return { ok: false, why: 'fewshot ' + i + ' exceeds ' + MAX_MSG + ' characters' };
    if (m.user.includes(FENCE) || m.assistant.includes(FENCE)) return { ok: false, why: 'fewshot ' + i + ' may not contain a triple-quote fence' };
  }
  if (!isObj(spec.params)) return { ok: false, why: 'a spec needs params' };
  if (!isNum(spec.params.temperature) || spec.params.temperature < TEMP_MIN || spec.params.temperature > TEMP_MAX) return { ok: false, why: 'temperature must be within ' + TEMP_MIN + '..' + TEMP_MAX };
  if (!isInt(spec.params.num_predict) || spec.params.num_predict < PREDICT_MIN || spec.params.num_predict > PREDICT_MAX) return { ok: false, why: 'num_predict must be an integer within ' + PREDICT_MIN + '..' + PREDICT_MAX };
  return { ok: true };
}

/** assembleModelfile(base, spec) — the deterministic mint: same spec, same bytes, every time. */
export function assembleModelfile(base, spec) {
  if (!isStr(base) || base.trim().length === 0) return { ok: false, why: 'a mint needs a base model name' };
  if (/\s/.test(base)) return { ok: false, why: 'a base model name may not contain whitespace' };
  const v = validSpec(spec);
  if (!v.ok) return v;
  const lines = [
    'FROM ' + base,
    'PARAMETER temperature ' + spec.params.temperature,
    'PARAMETER num_predict ' + spec.params.num_predict,
    'SYSTEM ' + FENCE + spec.system + FENCE,
  ];
  for (const m of spec.fewshot) {
    lines.push('MESSAGE user ' + FENCE + m.user + FENCE);
    lines.push('MESSAGE assistant ' + FENCE + m.assistant + FENCE);
  }
  return { ok: true, modelfile: lines.join('\n') + '\n' };
}

// ── the mint verdict: only a certified BEATS receipt mints a node ───────────────────────────────
export function mintVerdict(receipt) {
  if (!isObj(receipt)) return { ok: false, why: 'mintVerdict takes a receipt' };
  if (receipt.kind !== 'fallforge-gate-receipt') return { ok: false, why: 'not a fallforge-gate receipt' };
  if (!isStr(receipt.verdict)) return { ok: false, why: 'the receipt has no verdict' };
  if (receipt.verdict !== 'BEATS') return { ok: true, minted: false, why: 'the candidate did not beat its base — verdict ' + receipt.verdict };
  if (receipt.certified !== true) return { ok: true, minted: false, why: 'the win is not certified — not enough evidence' };
  return { ok: true, minted: true, why: 'certified BEATS — the mint measurably improved the base' };
}

// ── the manifest: the mint's whole story, canonically hashed, ready for a wallet signature ──────
export function makeManifest(m) {
  if (!isObj(m)) return { ok: false, why: 'makeManifest takes an object' };
  for (const f of ['node', 'base', 'limb', 'evalName', 'trainHash', 'modelfile', 'createdAt']) {
    if (!isStr(m[f]) || m[f].length === 0) return { ok: false, why: 'manifest needs a non-empty ' + f };
  }
  if (!isInt(m.rounds) || m.rounds < 1 || m.rounds > MAX_ROUNDS) return { ok: false, why: 'rounds must be an integer within 1..' + MAX_ROUNDS };
  if (m.trainHash.length !== 64 || !HEX.test(m.trainHash)) return { ok: false, why: 'trainHash must be 64 lowercase hex chars' };
  if (!Array.isArray(m.receipts) || m.receipts.length === 0) return { ok: false, why: 'a manifest carries at least one receipt reference' };
  for (const [i, r] of m.receipts.entries()) {
    if (!isObj(r) || !isStr(r.vs) || r.vs.length === 0) return { ok: false, why: 'receipt ' + i + ' needs a vs model name' };
    if (!isStr(r.hash) || r.hash.length !== 64 || !HEX.test(r.hash)) return { ok: false, why: 'receipt ' + i + ' needs a 64-hex hash' };
    if (!isStr(r.verdict) || r.verdict.length === 0) return { ok: false, why: 'receipt ' + i + ' needs a verdict' };
    if (typeof r.certified !== 'boolean') return { ok: false, why: 'receipt ' + i + ' needs a boolean certified flag' };
  }
  const mf = sha256(m.modelfile);
  if (!mf.ok) return { ok: false, why: mf.why };
  const body = {
    v: 1,
    kind: 'fallforge-mint-manifest',
    node: m.node, base: m.base, limb: m.limb,
    tuning: 'prompt-tuned (Modelfile) — weight-level LoRA is v2',
    rounds: m.rounds,
    evalName: m.evalName,
    trainHash: m.trainHash,
    modelfileHash: mf.hash,
    receipts: m.receipts.map((r) => ({ vs: r.vs, hash: r.hash, verdict: r.verdict, certified: r.certified })),
    createdAt: m.createdAt,
    scope: 'receipts are scoped to their probe sets — a mint is a measurement, never a general claim',
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, manifest: { ...body, hash: h.hash } };
}

/** signable(manifest) — the EXACT bytes a wallet signs: the canonical body, hash included. */
export function signable(manifest) {
  if (!isObj(manifest) || manifest.kind !== 'fallforge-mint-manifest' || !isStr(manifest.hash)) return { ok: false, why: 'signable takes a fallforge-mint manifest' };
  const unsigned = { ...manifest };
  delete unsigned.signature;
  return { ok: true, payload: canon(unsigned) };
}

export function attachSignature(manifest, pubHex, sigHex) {
  const s = signable(manifest);
  if (!s.ok) return s;
  if (!isStr(pubHex) || pubHex.length < 32 || pubHex.length % 2 !== 0 || !HEX.test(pubHex)) return { ok: false, why: 'public key must be even-length hex, at least 32 chars' };
  if (!isStr(sigHex) || sigHex.length !== 128 || !HEX.test(sigHex)) return { ok: false, why: 'an Ed25519 signature is 128 hex chars' };
  return { ok: true, manifest: { ...manifest, signature: { alg: 'Ed25519', pub: pubHex, sig: sigHex } } };
}

/** verifyManifest(m) — internal consistency: the facts match their own hash. Signature bytes are
 *  checked at the edge (WebCrypto / node:crypto) over signable(); the kernel pins WHAT is signed. */
export function verifyManifest(m) {
  if (!isObj(m) || m.kind !== 'fallforge-mint-manifest' || !isStr(m.hash)) return { ok: false, why: 'not a fallforge-mint manifest' };
  const body = { ...m };
  delete body.hash;
  delete body.signature;
  const h = sha256(canon({ ...body, }));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== m.hash) return { ok: true, valid: false, why: 'hash mismatch — the manifest does not match its own facts' };
  return { ok: true, valid: true, why: 'manifest intact' };
}
