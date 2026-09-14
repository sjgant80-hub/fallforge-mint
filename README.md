# FallForge Mint

**LIVE: https://sjgant80-hub.github.io/fallforge-mint/**

The sovereign-node minting pipeline — layer 2 of the sovereign-node factory. Point it at a
use-case (train examples + a held-out eval) and it mints an **owned, private, measurably better**
specialist from a small base model:

1. **The limb writes the spec** — a bigger model reads the TRAIN examples (never the eval) and
   distils a system prompt + few-shot exemplars.
2. **The kernel assembles the Modelfile** — deterministic, byte-pinned, bounded. Same spec, same
   bytes, every time.
3. **`ollama create` mints the node** — a named model artifact you own and run privately.
4. **[fallforge-gate](https://github.com/sjgant80-hub/fallforge-gate) measures it** against its
   raw base on the held-out eval. Not a certified BEATS? The limb sees its misses and refines —
   at most 5 rounds. **The pipeline cannot declare success, only measure it.**
5. **An Ed25519-signed manifest seals the whole mint** — node, base, limb, rounds, train hash,
   Modelfile hash, receipt hashes. The live page re-verifies everything in your browser.

## The shipped mint — real, reproduced in one round

`triage-1b` = `llama3.2:1b` prompt-tuned for support-ticket triage by limb `qwen2.5:14b`:

| Receipt | Result |
|---|---|
| **vs raw `llama3.2:1b`** | **BEATS, certified — 14/16 vs 11/16 (+19%)**. The mint measurably improved the base. |
| vs `qwen2.5:7b` (stretch) | LOSES — 14/16 vs 15/16. The minted 1B closed the gap on a model 7× its size (the raw base sat at 11) but does not beat it, and the receipt says so. It answers ~3× faster. |

That pair is the honest story: the gate's own repo ships the *before* receipt (raw 1B loses
badly); this repo ships the *after* — better than itself, still behind the big one, faster than
both claims suggest, all measured.

## Run it

```bash
node --test kernel.test.mjs                            # the suite
node tools/witness.mjs mutate kernel.mjs --timeout 20000 --cap 500 --test node --test kernel.test.mjs   # the gate
node mint.mjs --node triage-1b --base llama3.2:1b --limb qwen2.5:14b \
  --train datasets/support-triage-train.json --eval datasets/support-triage-eval.json \
  --rounds 3 --also qwen2.5:7b                         # a real mint vs a local Ollama
node make-page.mjs                                     # regenerate the page from the gated kernel
```

## Honest limits (v1)

- **v1 mints prompt-tuned nodes** — the specialization lives at the Modelfile level (system +
  exemplars + params), not in the weights. Weight-level LoRA is v2 and lands in these same
  gate/sign/export stages unchanged.
- **The signature proves the issuer's key, not their identity** — Ed25519 over the kernel-pinned
  payload; the private key never leaves the issuer's machine (`~/.fallforge/`, never committed).
- **Receipts are scoped** to their probe set; train and eval are disjoint and the train hash is
  inside the signed manifest.
- **A refused mint ships too** — no certified BEATS in any round means the manifest records the
  best round's honest numbers under NOT MINTED. The verdict comes from the gate, not the pipeline.

The kernel (`kernel.mjs`) is mutation-witnessed in CI (survivors need a written equivalence
argument); CI also re-verifies the shipped manifest's hash, its Ed25519 signature, and that the
shipped receipt and Modelfile match the signed manifest, then fails if the page drifts from the
kernel. MIT.
