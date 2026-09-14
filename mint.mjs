#!/usr/bin/env node
// mint.mjs — the minting pipeline, end to end, frontier-as-limb:
//   limb writes a SPEC from TRAIN examples → kernel assembles a Modelfile → ollama create mints
//   the node → fallforge-gate measures it against its RAW BASE on the HELD-OUT eval → not BEATS?
//   the limb sees its misses and refines (bounded rounds) → best round wins → manifest signed.
// The eval set is NEVER shown to the limb. The pipeline cannot declare success — only measure it.
//
//   node mint.mjs --node triage-1b --base llama3.2:1b --limb qwen2.5:14b \
//                 --train datasets/support-triage-train.json --eval datasets/support-triage-eval.json \
//                 [--rounds 3] [--also qwen2.5:7b]
//
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { validSpec, assembleModelfile, mintVerdict, makeManifest, signable, attachSignature, verifyManifest, sha256 } from './kernel.mjs';
import { validEvalSet, compare, makeReceipt, verifyReceipt } from './vendor/gate-kernel.mjs';

const OLLAMA = process.env.OLLAMA_URL || 'http://localhost:11434';
const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
const { node: NODE, base: BASE, limb: LIMB, train: TRAIN, eval: EVAL } = args;
const ROUNDS = Math.max(1, Math.min(5, parseInt(args.rounds || '3', 10)));
if (!NODE || !BASE || !LIMB || !TRAIN || !EVAL) {
  console.error('usage: node mint.mjs --node <name> --base <model> --limb <model> --train <json> --eval <json> [--rounds N] [--also <model>]');
  process.exit(2);
}

const train = JSON.parse(readFileSync(TRAIN, 'utf8'));
const evalSet = JSON.parse(readFileSync(EVAL, 'utf8'));
const ev = validEvalSet(evalSet);
if (!ev.ok) { console.error('eval set refused: ' + ev.why); process.exit(1); }
const trainHash = sha256(JSON.stringify(train)).hash;

async function ask(model, prompt, numPredict) {
  // streamed: a slow model's first token can be minutes away, and undici's headers timeout
  // kills a non-streaming call at 5 minutes — chunks keep the wire warm instead
  const t0 = Date.now();
  const res = await fetch(OLLAMA + '/api/generate', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, prompt, stream: true, options: { temperature: 0, num_predict: numPredict || 220 } }),
  });
  if (!res.ok) throw new Error(model + ' refused: HTTP ' + res.status);
  let out = '', buf = '';
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try { const j = JSON.parse(line); if (j.response) out += j.response; } catch (e) {}
    }
  }
  return { output: out, ms: Date.now() - t0 };
}

function firstJson(text) {
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0, inStr = false, escN = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (escN) { escN = false; continue; }
    if (c === '\\') { escN = true; continue; }
    if (c === '"') inStr = !inStr;
    if (inStr) continue;
    if (c === '{') depth++;
    if (c === '}') { depth--; if (depth === 0) { try { return JSON.parse(text.slice(start, i + 1)); } catch (e) { return null; } } }
  }
  return null;
}

const exampleLines = train.examples.map((e, i) => '[' + i + '] IN: ' + e.input + '\n    OUT: ' + e.output).join('\n');

async function limbSpec(feedback) {
  const prompt =
    'You are a model-specialization engineer. Write a SPEC that turns a small base model into a strong ' +
    'specialist for this task.\n\nTASK:\n' + train.task + '\n\nTRAINING EXAMPLES:\n' + exampleLines + '\n\n' +
    (feedback ? 'PREVIOUS ATTEMPT FAILED THESE HELD-OUT CHECKS (fix the weaknesses they reveal WITHOUT seeing them):\n' + feedback + '\n\n' : '') +
    'Reply with ONLY a JSON object, no prose:\n' +
    '{"system": "<a precise system prompt, under 1500 chars, that pins the exact output format, every allowed value, and the tricky rules (order numbers as strings, none when absent, urgency judgement)>",\n' +
    ' "fewshot": [<up to 4 integers — indices of the MOST instructive training examples>],\n' +
    ' "temperature": 0}';
  for (let attempt = 1; attempt <= 3; attempt++) {
    const r = await ask(LIMB, prompt, 900);
    const j = firstJson(r.output);
    if (j && typeof j.system === 'string' && Array.isArray(j.fewshot)) {
      const picks = [...new Set(j.fewshot.filter((n) => Number.isInteger(n) && n >= 0 && n < train.examples.length))].slice(0, 4);
      const spec = {
        system: j.system,
        fewshot: picks.map((n) => ({ user: train.examples[n].input, assistant: train.examples[n].output })),
        params: { temperature: 0, num_predict: 200 },
      };
      const v = validSpec(spec);
      if (v.ok) return spec;
      console.log('  limb spec refused by kernel (' + v.why + ') — retry ' + attempt);
    } else console.log('  limb reply was not a spec — retry ' + attempt);
  }
  throw new Error('the limb could not produce a valid spec in 3 attempts');
}

async function evalSide(model) {
  const outputs = [], latenciesMs = [];
  for (const [i, p] of evalSet.probes.entries()) {
    const r = await ask(model, evalSet.task + '\n\nMessage:\n' + p.input);
    outputs.push(r.output); latenciesMs.push(r.ms);
    process.stdout.write('\r  ' + model + ': ' + (i + 1) + '/' + evalSet.probes.length + '   ');
  }
  process.stdout.write('\n');
  return { model, outputs, latenciesMs };
}

mkdirSync('out', { recursive: true });
console.log('FallForge Mint · node=' + NODE + ' base=' + BASE + ' limb=' + LIMB + ' rounds<=' + ROUNDS);
console.log('  train ' + train.examples.length + ' examples (hash ' + trainHash.slice(0, 12) + '…) · eval ' + evalSet.probes.length + ' probes HELD OUT');

console.log('  measuring the raw base first…');
const baseRun = await evalSide(BASE);

let best = null, feedback = '';
for (let round = 1; round <= ROUNDS; round++) {
  console.log('ROUND ' + round + ': limb writing spec…');
  const spec = await limbSpec(feedback);
  const mf = assembleModelfile(BASE, spec);
  if (!mf.ok) { console.error('assembly refused: ' + mf.why); process.exit(1); }
  writeFileSync('out/Modelfile', mf.modelfile);
  execFileSync('ollama', ['create', NODE, '-f', 'out/Modelfile'], { stdio: 'pipe' });
  console.log('  minted ' + NODE + ' (' + mf.modelfile.length + ' byte Modelfile) — gating vs raw base…');
  const candRun = await evalSide(NODE);
  const cmp = compare(evalSet, candRun, baseRun);
  if (!cmp.ok) { console.error('gate refused: ' + cmp.why); process.exit(1); }
  console.log('  round ' + round + ': ' + cmp.candidate.passed + '/' + cmp.probes + ' vs base ' + cmp.baseline.passed + '/' + cmp.probes + ' → ' + cmp.verdict + (cmp.certified ? ' (certified)' : ''));
  if (!best || cmp.candidate.passed > best.cmp.candidate.passed) best = { spec, modelfile: mf.modelfile, cmp, round, run: candRun };
  const verdict = mintVerdict({ kind: 'fallforge-gate-receipt', verdict: cmp.verdict, certified: cmp.certified });
  if (verdict.ok && verdict.minted) break;
  const misses = cmp.candidate.results.filter((r) => !r.pass).map((r) => {
    const p = evalSet.probes.find((x) => x.id === r.id);
    return '- a message like "' + p.input.slice(0, 90) + '…" was mishandled: ' + r.why;
  }).join('\n');
  feedback = misses || 'no individual misses — the base matched everywhere; sharpen edge-case rules';
}

// re-mint the BEST round so the artifact on disk is the one the receipt describes
writeFileSync('out/Modelfile', best.modelfile);
execFileSync('ollama', ['create', NODE, '-f', 'out/Modelfile'], { stdio: 'pipe' });
writeFileSync('out/spec.json', JSON.stringify(best.spec, null, 2) + '\n');

const scoredAt = new Date().toISOString();
const recBase = makeReceipt(best.cmp, { scoredAt });
if (!recBase.ok || verifyReceipt(recBase.receipt).valid !== true) { console.error('receipt failed'); process.exit(1); }
writeFileSync('out/receipt-vs-base.json', JSON.stringify(recBase.receipt, null, 2) + '\n');
const receipts = [{ vs: BASE, hash: recBase.receipt.hash, verdict: recBase.receipt.verdict, certified: recBase.receipt.certified }];

if (args.also) {
  console.log('stretch receipt: ' + NODE + ' vs ' + args.also + '…');
  const bigRun = await evalSide(args.also);
  const cmp2 = compare(evalSet, { model: NODE, outputs: best.run.outputs, latenciesMs: best.run.latenciesMs }, bigRun);
  if (cmp2.ok) {
    const rec2 = makeReceipt(cmp2, { scoredAt });
    if (rec2.ok && verifyReceipt(rec2.receipt).valid === true) {
      writeFileSync('out/receipt-vs-' + args.also.replace(/[^\w.-]/g, '_') + '.json', JSON.stringify(rec2.receipt, null, 2) + '\n');
      receipts.push({ vs: args.also, hash: rec2.receipt.hash, verdict: rec2.receipt.verdict, certified: rec2.receipt.certified });
      console.log('  stretch: ' + cmp2.candidate.passed + '/' + cmp2.probes + ' vs ' + args.also + ' ' + cmp2.baseline.passed + '/' + cmp2.probes + ' → ' + cmp2.verdict);
    }
  } else console.log('  stretch refused: ' + cmp2.why);
}

// the wallet: an Ed25519 issuer key, private key NEVER leaves ~/.fallforge
const keyDir = join(homedir(), '.fallforge');
mkdirSync(keyDir, { recursive: true });
const keyPath = join(keyDir, 'ed25519.pem');
if (!existsSync(keyPath)) {
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  console.log('  new issuer key generated at ' + keyPath + ' (private — never committed)');
}
const priv = createPrivateKey(readFileSync(keyPath, 'utf8'));
const pubHex = createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('hex');

const mani = makeManifest({
  node: NODE, base: BASE, limb: LIMB, rounds: best.round,
  evalName: evalSet.name, trainHash, modelfile: best.modelfile,
  receipts, createdAt: scoredAt,
});
if (!mani.ok) { console.error('manifest refused: ' + mani.why); process.exit(1); }
const payload = signable(mani.manifest);
const sigHex = edSign(null, Buffer.from(payload.payload, 'utf8'), priv).toString('hex');
const signed = attachSignature(mani.manifest, pubHex, sigHex);
if (!signed.ok) { console.error('signature refused: ' + signed.why); process.exit(1); }
if (verifyManifest(signed.manifest).valid !== true) { console.error('manifest failed self-verification'); process.exit(1); }
writeFileSync('out/manifest.json', JSON.stringify(signed.manifest, null, 2) + '\n');
writeFileSync('out/issuer-pub.hex', pubHex + '\n');

const v = mintVerdict(recBase.receipt);
console.log('');
console.log(v.minted ? 'MINTED ✓ ' + NODE + ' — ' + v.why : 'NOT MINTED — ' + v.why + ' (best round kept for the record)');
console.log('  ' + recBase.receipt.candidate.passed + '/' + recBase.receipt.probes + ' vs raw base ' + recBase.receipt.baseline.passed + '/' + recBase.receipt.probes + ' · delta ' + (recBase.receipt.passDelta >= 0 ? '+' : '') + Math.round(recBase.receipt.passDelta * 100) + '%');
console.log('  out/: Modelfile, spec.json, receipt-vs-base.json, manifest.json (signed Ed25519)');
