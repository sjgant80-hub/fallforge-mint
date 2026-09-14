// FallForge Gate — the proof-of-play harness for small language models. The pure, gated core:
// deterministic scorers (no LLM judge — correlated checkers give false confidence), exact
// measurement of a CANDIDATE model against a BASELINE on a named use-case, a verdict that can
// and does say LOSES, and a tamper-evident receipt whose numbers are measured, never asserted.
// No I/O here — runners call models and bring outputs; the kernel only measures and refuses.
// Pure and total: garbage in → { ok:false, why }, never a throw.

export const MIN_PROBES = 10;        // below this a verdict is evidence-free — the gate refuses to certify
export const SCORER_TYPES = Object.freeze(['exact', 'contains', 'number', 'json-field']);

const isStr = (v) => typeof v === 'string';
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

// ── SHA-256, pure and synchronous (receipts hash on the real thing) ─────────────────────────────
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

/** canon(v) — canonical JSON: sorted keys, so the same facts always hash the same. */
export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── the eval set: a named use-case with deterministic probes ────────────────────────────────────
function validExpect(x) {
  if (!isObj(x) || !isStr(x.type)) return 'each probe needs an expect object with a type';
  if (!SCORER_TYPES.includes(x.type)) return 'unknown scorer type: ' + x.type;
  if (x.type === 'exact' && !isStr(x.value)) return 'exact expects a string value';
  if (x.type === 'contains') {
    if (!Array.isArray(x.all) || x.all.length === 0) return 'contains expects a non-empty array named all';
    for (const s of x.all) if (!isStr(s) || s.length === 0) return 'each contains entry must be a non-empty string';
  }
  if (x.type === 'number') {
    if (!isNum(x.value)) return 'number expects a numeric value';
    if (!isNum(x.tolerance) || x.tolerance < 0) return 'number expects a non-negative tolerance';
  }
  if (x.type === 'json-field') {
    if (!isStr(x.field) || x.field.length === 0) return 'json-field expects a field path';
    if (!isStr(x.value) && !isNum(x.value) && typeof x.value !== 'boolean') return 'json-field expects a string, number or boolean value';
  }
  return null;
}

export function validEvalSet(es) {
  if (!isObj(es)) return { ok: false, why: 'an eval set is an object' };
  if (!isStr(es.name) || es.name.length === 0) return { ok: false, why: 'an eval set needs a name' };
  if (!isStr(es.task) || es.task.length === 0) return { ok: false, why: 'an eval set needs a task description' };
  if (!Array.isArray(es.probes) || es.probes.length === 0) return { ok: false, why: 'an eval set needs a non-empty probes array' };
  const seen = new Set();
  for (const p of es.probes) {
    if (!isObj(p) || !isStr(p.id) || p.id.length === 0) return { ok: false, why: 'each probe needs a string id' };
    if (seen.has(p.id)) return { ok: false, why: 'duplicate probe id: ' + p.id };
    seen.add(p.id);
    if (!isStr(p.input) || p.input.length === 0) return { ok: false, why: 'probe ' + p.id + ' needs an input' };
    const bad = validExpect(p.expect);
    if (bad) return { ok: false, why: 'probe ' + p.id + ': ' + bad };
  }
  return { ok: true, probes: es.probes.length };
}

// ── the scorers: deterministic, independent, no judge model ─────────────────────────────────────
const norm = (s) => s.trim().replace(/\s+/g, ' ');

function jsonField(output, path) {
  // the model may wrap JSON in prose or fences — score the first balanced object found
  const start = output.indexOf('{');
  if (start === -1) return { found: false };
  let depth = 0, end = -1, inStr = false, escNext = false;
  for (let i = start; i < output.length; i++) {
    const c = output[i];
    if (escNext) { escNext = false; continue; }
    if (c === '\\') { escNext = true; continue; }
    if (c === '"') inStr = !inStr;
    if (inStr) continue;
    if (c === '{') depth++;
    if (c === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  if (end === -1) return { found: false };
  let obj;
  try { obj = JSON.parse(output.slice(start, end + 1)); } catch (e) { return { found: false }; }
  let cur = obj;
  for (const part of path.split('.')) {
    if (!isObj(cur) || !(part in cur)) return { found: false };
    cur = cur[part];
  }
  return { found: true, value: cur };
}

export function scoreProbe(probe, output) {
  if (!isObj(probe) || !isObj(probe.expect)) return { ok: false, why: 'scoreProbe takes a probe with an expect' };
  const bad = validExpect(probe.expect);
  if (bad) return { ok: false, why: bad };
  if (!isStr(output)) return { ok: true, pass: false, why: 'no output produced' };
  const x = probe.expect;
  if (x.type === 'exact') {
    const a = x.caseSensitive === true ? norm(output) : norm(output).toLowerCase();
    const b = x.caseSensitive === true ? norm(x.value) : norm(x.value).toLowerCase();
    return { ok: true, pass: a === b, why: a === b ? 'exact match' : 'expected exactly: ' + x.value };
  }
  if (x.type === 'contains') {
    const hay = output.toLowerCase();
    for (const s of x.all) if (!hay.includes(s.toLowerCase())) return { ok: true, pass: false, why: 'missing: ' + s };
    return { ok: true, pass: true, why: 'all present' };
  }
  if (x.type === 'number') {
    const m = output.replace(/,/g, '').match(/-?\d+(\.\d+)?/);
    if (!m) return { ok: true, pass: false, why: 'no number in output' };
    const got = parseFloat(m[0]);
    const pass = Math.abs(got - x.value) <= x.tolerance;
    return { ok: true, pass, why: pass ? 'number within tolerance' : 'got ' + got + ', expected ' + x.value + ' plus or minus ' + x.tolerance };
  }
  // json-field
  const f = jsonField(output, x.field);
  if (!f.found) return { ok: true, pass: false, why: 'field ' + x.field + ' not found in any JSON object in the output' };
  const pass = isStr(f.value) && isStr(x.value)
    ? norm(f.value).toLowerCase() === norm(x.value).toLowerCase()
    : f.value === x.value;
  return { ok: true, pass, why: pass ? 'field matches' : 'field ' + x.field + ' is ' + JSON.stringify(f.value) + ', expected ' + JSON.stringify(x.value) };
}

/** scoreRun(evalSet, outputs) — score one model's outputs against every probe, in order. */
export function scoreRun(evalSet, outputs) {
  const v = validEvalSet(evalSet);
  if (!v.ok) return v;
  if (!Array.isArray(outputs)) return { ok: false, why: 'outputs must be an array of strings' };
  if (outputs.length !== evalSet.probes.length) return { ok: false, why: 'outputs length ' + outputs.length + ' does not match ' + evalSet.probes.length + ' probes' };
  const results = [];
  let passed = 0;
  for (let i = 0; i < evalSet.probes.length; i++) {
    const r = scoreProbe(evalSet.probes[i], outputs[i]);
    if (!r.ok) return { ok: false, why: 'probe ' + evalSet.probes[i].id + ': ' + r.why };
    if (r.pass) passed++;
    results.push({ id: evalSet.probes[i].id, pass: r.pass, why: r.why });
  }
  return { ok: true, results, passed, total: evalSet.probes.length, passRate: passed / evalSet.probes.length };
}

// ── the comparison: candidate vs baseline, measured — a verdict that can say LOSES ──────────────
function validSide(side, label) {
  if (!isObj(side)) return label + ' must be an object';
  if (!isStr(side.model) || side.model.length === 0) return label + ' needs a model name';
  if (!Array.isArray(side.outputs)) return label + ' needs an outputs array';
  if (!Array.isArray(side.latenciesMs)) return label + ' needs a latenciesMs array';
  if (side.latenciesMs.length !== side.outputs.length) return label + ' latencies must match outputs one to one';
  for (const l of side.latenciesMs) if (!isNum(l) || l < 0) return label + ' latencies must be non-negative numbers';
  return null;
}

export function compare(evalSet, candidate, baseline) {
  const v = validEvalSet(evalSet);
  if (!v.ok) return v;
  for (const [side, label] of [[candidate, 'candidate'], [baseline, 'baseline']]) {
    const bad = validSide(side, label);
    if (bad) return { ok: false, why: bad };
  }
  if (candidate.model === baseline.model) return { ok: false, why: 'candidate and baseline are the same model — nothing is being compared' };
  const cr = scoreRun(evalSet, candidate.outputs);
  if (!cr.ok) return { ok: false, why: 'candidate: ' + cr.why };
  const br = scoreRun(evalSet, baseline.outputs);
  if (!br.ok) return { ok: false, why: 'baseline: ' + br.why };
  const mean = (a) => a.length === 0 ? 0 : a.reduce((s, x) => s + x, 0) / a.length;
  const candMs = mean(candidate.latenciesMs), baseMs = mean(baseline.latenciesMs);
  // delta from INTEGER counts — subtracting two rounded rates would smuggle float drift into a receipt
  const passDelta = (cr.passed - br.passed) / evalSet.probes.length;
  const verdict = passDelta > 0 ? 'BEATS' : passDelta < 0 ? 'LOSES' : 'MATCHES';
  // certification needs evidence: enough probes, and a strictly better pass rate
  const certified = evalSet.probes.length >= MIN_PROBES && passDelta > 0;
  return {
    ok: true,
    task: evalSet.name,
    probes: evalSet.probes.length,
    candidate: { model: candidate.model, passed: cr.passed, passRate: cr.passRate, meanMs: candMs, results: cr.results },
    baseline: { model: baseline.model, passed: br.passed, passRate: br.passRate, meanMs: baseMs, results: br.results },
    passDelta,
    speedX: candMs > 0 ? baseMs / candMs : 0,
    verdict,
    certified,
    why: certified ? 'measured on ' + evalSet.probes.length + ' probes — candidate strictly better'
      : evalSet.probes.length < MIN_PROBES ? 'not certifiable: fewer than ' + MIN_PROBES + ' probes is not evidence'
      : 'not certified: the candidate did not strictly beat the baseline',
  };
}

// ── the receipt: measured facts, canonically hashed — tamper shows ──────────────────────────────
export function makeReceipt(cmp, meta) {
  if (!isObj(cmp) || cmp.ok !== true || !isStr(cmp.verdict)) return { ok: false, why: 'makeReceipt takes a successful compare result' };
  if (!isObj(meta) || !isStr(meta.scoredAt) || meta.scoredAt.length === 0) return { ok: false, why: 'meta needs a scoredAt timestamp string' };
  const body = {
    v: 1,
    kind: 'fallforge-gate-receipt',
    task: cmp.task,
    probes: cmp.probes,
    candidate: { model: cmp.candidate.model, passed: cmp.candidate.passed, passRate: cmp.candidate.passRate, meanMs: Math.round(cmp.candidate.meanMs) },
    baseline: { model: cmp.baseline.model, passed: cmp.baseline.passed, passRate: cmp.baseline.passRate, meanMs: Math.round(cmp.baseline.meanMs) },
    passDelta: cmp.passDelta,
    speedX: Math.round(cmp.speedX * 100) / 100,
    verdict: cmp.verdict,
    certified: cmp.certified,
    scoredAt: meta.scoredAt,
    scope: 'this probe set only — a receipt is a measurement, never a general claim',
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, receipt: { ...body, hash: h.hash } };
}

export function verifyReceipt(r) {
  if (!isObj(r) || !isStr(r.hash)) return { ok: false, why: 'a receipt is an object with a hash' };
  if (r.kind !== 'fallforge-gate-receipt') return { ok: false, why: 'not a fallforge-gate receipt' };
  const body = { ...r };
  delete body.hash;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== r.hash) return { ok: true, valid: false, why: 'hash mismatch — the receipt does not match its own facts' };
  return { ok: true, valid: true, why: 'receipt intact' };
}
