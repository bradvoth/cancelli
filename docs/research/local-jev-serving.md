# Local Jev-compatible backend — serving mechanics (research, 2026-09-22)

Legend: **[LOCAL]** checked on this machine; **[DOC]** cited URL; **[INFER]** my reasoning, not verified.

## 0. Local facts checked

- Hardware [LOCAL]: `Apple M5`, `hw.memsize` = 34359738368 (32 GiB).
- Runtimes [LOCAL]:
  - `ollama --version` → **0.34.2**. Installed models (`ollama list`): qwen3.5:0.8b-mlx, nemotron-3.5-lightning:30b-mlx (22 GB),
    qwen3.6:27b-mtp-q4_K_M (17 GB), gemma4:12b-it-qat (7.2 GB), gemma4:12b, qwen3.6:27b-coding-nvfp4, qwen3.6:35b-a3b-coding-nvfp4, qwen3.6:latest.
    Note several are `-mlx` / nvfp4 tags → Ollama's MLX engine, not only the GGML runner (matters for logprob support, §1).
  - `llama-server --version` → `version: 0.4.0 (build 10809, commit 5266f24da)`, AppleClang 21, Darwin arm64 (Homebrew).
  - LM Studio app `CFBundleShortVersionString` = **0.4.11+1**; `lms` CLI commit 0b2a176. `lms ls`: gemma-4-26b-a4b-it-claude-opus-distill (26B-A4B MoE, 19.09 GB), nomic-embed-text-v1.5.
    (Side effect: `lms ls` woke the LM Studio background service.)
- cancelli Jev path [LOCAL, /Users/brad/Documents/cancelli/src/jev/{client.rs,mod.rs,decide.rs}, src/config.rs]:
  - `client::post` POSTs `{base_url}/v1/systemone` with `Authorization: Bearer <key>`; ureq 3 (rustls) — plain `http://127.0.0.1:…` works (config tests use `http://127.0.0.1:9`).
  - Per-attempt `judge.timeout_ms` default **3000**, total `judge.budget_ms` default **5000**, one retry on 408/429/5xx/timeout.
  - A key is **mandatory** (`resolve_key` errors if neither env nor 0600 file) — a local sidecar would need a dummy key.
  - `mod.rs:283` hard-fails if `response.model != PINNED_MODEL` (`"jev-1.13.0"`, a `const`) — a sidecar must either echo `jev-1.13.0` (lying in logs) or cancelli must make the pin configurable per backend.
  - `decide::check_complete` requires every sent axis back with matching `type` and a finite reading (noul→`noul`, score→`score`, choice→non-empty `probabilities`). `usage` optional. `legend`/`confidence` not required for decisions.
- Jev reference latency [LOCAL, /Users/brad/Documents/tte/data/runs/procreations_v2.manifest.json]: 5,750 calls, mean **260 ms**, p50 234 ms, p95 449 ms; 19.55 M input tokens → **~3,400 input tokens/call** (state + 39 questions as billed).
- Validation data layout [LOCAL]:
  - `/Users/brad/Documents/tte/data/cache/jev-1.13.0/<rubric_hash>/<sha256>.json` — dirs `0fd1f245ae1c7ef3` (8,984 files, current rubric v2), `4516e5fdd90e947f` (19,191, v1), `f62dac1447f399a8` (10). Each file: `{answers, model, usage, request_id, elapsed_ms, error}` — **no state text**; key is a hash.
  - `/Users/brad/Documents/tte/data/runs/*.jsonl` — one record per item: `item_id, source, label ("approve"/"deny"), category, context_level, state_hash, rubric_hash, state_rendered, answers, model, usage, elapsed_ms, error`. This is the join you want (state + label + Jev answers in one row). `procreations_v{1,2,3}.jsonl` 5,750 rows each (2,250 approve / 3,500 deny); ablation runs per level L0–L4; atbench, l5_dataflow, scan runs.
  - `/Users/brad/Documents/tte/data/corpus/*.jsonl` — raw items (`raw: {user_request, history, call, label, category, difficulty, rationale, framework}`).

## 1. Probability extraction per runtime

### 1a. llama.cpp `llama-server` (installed build 10809 / commit 5266f24da; source read at master 2026-09-22)
Sources: README https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md ; source
`tools/server/server-common.cpp` (OAI param mapping), `server-context.cpp` (`populate_token_probs`), `server-task.cpp` (JSON shape).
- **Native `/completion`**: request `n_probs: N` (+ optional `post_sampling_probs: bool`). Response
  `completion_probabilities: [{id, token, bytes, logprob, top_logprobs: [{id, token, bytes, logprob}, …]}]`, one entry per generated token.
  With `post_sampling_probs: true` the keys become `prob` / `top_probs` (0–1) and may have < N entries. [DOC README l.579–657]
- **OpenAI `/v1/chat/completions` and `/v1/completions`**: `logprobs: true` + `top_logprobs: N` → mapped to `n_probs = top_logprobs` (default **20** if omitted);
  `top_logprobs` without `logprobs:true` is a 400. Response at `choices[0].logprobs.content[]` with the same `{id, token, bytes, logprob, top_logprobs}` items
  (code comment: "not yet OAI-compatible" — extra `id` field). [DOC server-common.cpp l.1403–1411, server-task.cpp l.434]
- **Max N**: no server cap found in source — clamped only to vocab size (`n_probs = min(max_probs, n_probs_request)`). [DOC server-context.cpp `populate_token_probs`] (Larger N costs a partial sort over vocab per token; cheap for 1 token.)
- **Raw vs post-filter**: default (`post_sampling_probs` false) = `get_token_probabilities()` = softmax over the **raw model logits** (`llama_get_logits_ith`), i.e. *before* temperature, top-k/p, min-p, `logit_bias` and **grammar** (all of which are samplers). README: "for temperature < 0 … probabilities are still being calculated via a simple softmax of the logits without considering any other sampler settings". [DOC] ⇒ You get the model's unconstrained next-token distribution even when a grammar forces the sampled token — exactly what calibration wants.
  Caveat [DOC server-context.cpp l.1790]: raw probs disable the experimental `--backend-sampling` path (not default).
- Extra endpoints useful for a backend: `POST /tokenize` (check label → token ids), `POST /apply-template` (render chat template to a string so you can then call `/completion` with an exact prompt), `return_tokens`, `id_slot`, `cache_prompt`, `n_cache_reuse`. [DOC README]

### 1b. Ollama 0.34.2 (source read at tag v0.34.2)
Sources: https://docs.ollama.com/api/chat ; `server/routes.go`, `server/logprob.go`, `llm/llama_server.go`, `mlxrunner/sample/sample.go`, `openai/openai.go` at https://github.com/ollama/ollama/tree/v0.34.2
- Native `/api/chat` and `/api/generate`: `"logprobs": true, "top_logprobs": N`; response `logprobs: [{token, logprob, bytes, top_logprobs: [{token, logprob, bytes}]}]` (no token id). [DOC docs + logprob.go]
- **Max `top_logprobs` = 20** — hard validation: `"top_logprobs must be between 0 and 20"` (routes.go l.276, 318, 2489, 2531). [DOC]
- OpenAI-compat `/v1/chat/completions`: `logprobs` (bool) + `top_logprobs` (int) → `choices[].logprobs.content[]`; `/v1/completions` takes `logprobs` (int). [DOC openai.go l.126–166]
- **Architecture change (important)**: in 0.34.x Ollama no longer has its own GGML runner — GGUF models run in a **llama-server subprocess** (`llm/llama_server.go`: "wraps the llama-server binary as a subprocess"), launched with `-c NumCtx*numParallel -np numParallel`, requests sent to `/completion` with `cache_prompt: true` and `n_probs = max(top_logprobs,1)`, **no `post_sampling_probs`** ⇒ same raw-logit semantics as 1a. `format` → llama-server `json_schema` (or a JSON GBNF for `"json"`). [DOC llama_server.go l.1–10, 376–377, 1576–1605]
- **MLX models** (`*-mlx`, nvfp4 tags — several installed here) run in `mlxrunner`: logprobs = "Log-softmax over original logits" but the `logits` passed to `Sample` are **already grammar-masked** when `format` is set (`pipeline.go` l.399–409: `logits = grammarEngine.mask(...)` then `t.sample(logits)`). So **on MLX, a `format` constraint changes the reported logprobs** (renormalised over allowed tokens, masked tokens = −inf); temperature/top-k are not applied to them. [DOC sample.go l.433–450, pipeline.go] [INFER: exact numeric effect not tested]
- Top-20 cap + no token ids + no "logprob of token X" query means: if a label token falls outside the top 20 you only know it's < the 20th value — fine for binary (mass is concentrated) but lossy for 5-way score/choice tails.

### 1c. LM Studio 0.4.11 (app) / lms CLI
- Logprobs added in **0.3.39** via the **Open Responses** endpoint `POST /v1/responses` with `"include": ["message.output_text.logprobs"], "top_logprobs": K`; response items `{token, logprob, bytes, top_logprobs:[…]}`. [DOC https://lmstudio.ai/blog/openresponses]
- `/v1/chat/completions` documented params: model, top_p, top_k, messages, temperature, max_tokens, stream, stop, presence/frequency_penalty, logit_bias, repeat_penalty, seed — **no logprobs listed**. [DOC https://lmstudio.ai/docs/developer/openai-compat/chat-completions]
- Max K, raw-vs-post-sampling, and grammar interaction: **not documented; I don't know**. Would need an empirical probe (not run — would load a model).
- Engine is llama.cpp ("llm-engine" v2) or mlx-engine; continuous batching / "Max Concurrent Predictions" (default 4) on llama.cpp engine, "MLX coming soon" at 0.4.0. [DOC https://lmstudio.ai/docs/app/advanced/parallel-requests, https://lmstudio.ai/blog/0.4.0]

### 1d. Mapping Jev primitives to token probabilities [INFER — design]
Use raw next-token distribution at the **first answer position**, `max_tokens: 1`, `temperature: 0`:
- **noul**: prompt ends "Answer: " (or assistant turn prefilled) asking for `true`/`false` (or `Yes`/`No`). p = P(t_true) / (P(t_true)+P(t_false)), summing over tokenizer variants (`true`, ` true`, `True`, ` True`) looked up via `/tokenize` at startup. Report `other_mass = 1 − (P_true+P_false)` as a health metric; if large (>0.2), prompt is broken for that model.
- **choice**: relabel options as single-token letters `A..E` (b3 has 5, a6 has 4 options; all ≤ 26), present "A) localhost — desc", read P(A..E), renormalise, map back to label names → `probabilities{label:p}`, `choice=argmax`, `confidence=max p` [INFER: Jev's confidence formula is unpublished].
- **score**: levels 0..(n−1) ≤ 9 so digits are single tokens in most tokenizers (Llama-3/Qwen/Gemma all have single-digit tokens [INFER, verify via /tokenize]); `probabilities{"0":p0..}` renormalised; `score = Σ k·p_k`; `legend` = echo criteria; `confidence = max p`.
- Letters/digits must be checked per tokenizer: some tokenizers merge leading space (" A" vs "A"); prefill the assistant turn so the next token is unambiguous (e.g. template ends `Answer: (` for letters).
- Because llama-server returns raw logits' softmax, you can let the grammar force a valid token (so `content` is always valid) while reading unconstrained probabilities — the renormalisation handles leakage. On Ollama-MLX, don't set `format` (masking alters logprobs); rely on the prompt.

## 2. Efficiency: ~39 independent questions on one shared state

### 2a. What the workload actually is (measured locally)
- State is **small** in the offline corpora [LOCAL, runs/*.jsonl `state_rendered`]: procreations_v2 p50/p90/p99 = 558 / 854 / 1,276 chars; ablation L3 969 / 1,509 / 1,988; atbench 741 / 1,380 / 3,706 chars
  → roughly **150–1,000 tokens** (≈4 chars/token [INFER]).
- The **rubric text dominates**: 40 axes, instructions+criteria = 11,574 chars total (p50 264, max 655 per question) [LOCAL, tte/rubrics/v1_policy_distilled.yaml] ≈ **~2.9k tokens**; Jev bills ~3,400 input tokens/call ≈ state + all questions once each.
- So "3–7k tokens" is state+questions, not state alone. Live cancelli states may be larger (transcript context at L2) — treat S as a variable.

### 2b. Caching mechanics per runtime
- **llama-server** [DOC README + server-context.cpp]:
  - `cache_prompt` (default true): a slot keeps its last prompt's KV; a new request on that slot only evaluates the suffix after the longest common prefix.
  - `--cache-ram N` (default 8192 MiB, PR #16391): host-RAM prompt cache; on slot assignment the slot's old prompt is saved and the best-LCP cached prompt is **loaded into the slot** (`prompt_save`/`prompt_load`), so a prefix computed on one slot can be reused by another *later* request.
  - `-np/--parallel N` slots + continuous batching (default on); `-kvu` unified KV (default when slots=auto); `--slot-prompt-similarity` for slot selection; `id_slot` to pin.
  - **Cross-slot zero-copy prefix sharing (`seq_cp`) is used only for `n_cmpl>1` children of the same prompt** (`copy_state_to`, server-context.cpp l.722, 3758–3776) — NOT for 39 different suffixes. ⇒ If you fire 39 requests concurrently on a cold cache, each slot prefills the whole state (39×S). Correct pattern: **one warm-up request (state, or state+Q1) first, then the other 38** (sequential on 1 slot, or parallel after warm-up so `prompt_load` restores the prefix).
  - `--cache-reuse N` (KV shifting of non-prefix chunks) is irrelevant if layout is prefix-stable; `/slots/{id}?action=save|restore` can persist a rubric prefix to disk (`--slot-save-path`).
  - README warns logits are not bit-identical between batch sizes when cache is on → tiny nondeterminism in probabilities [DOC l.587].
- **Ollama 0.34.2**: GGUF → llama-server subprocess with `cache_prompt: true`, `-np OLLAMA_NUM_PARALLEL`; same semantics as above but you can't pass `id_slot`/`cache-ram` tuning [DOC llama_server.go]. MLX models → `mlxrunner/prefix_cache.go`: a **compressed prefix trie with per-layer KV snapshots shared across conversations**; switching branches "pages in the new path from its snapshots" ⇒ branching suffixes off a shared state are cached by design [DOC source]; `prompt_eval_cached_count` in responses shows hits [DOC docs.ollama.com/api/chat]. Keep model resident: `keep_alive: -1` / `OLLAMA_KEEP_ALIVE=-1` (default unload after 5 min → multi-second reload of a 17–22 GB model).
- **LM Studio 0.4.x**: continuous batching on llama.cpp engine ("Max Concurrent Predictions", default 4; unified KV default on) [DOC https://lmstudio.ai/docs/app/advanced/parallel-requests]; "token caching" mentioned for /v1/responses [DOC blog/openresponses]; prefix-cache semantics otherwise undocumented.

### 2c. Can one request score all questions?
- Through the servers: **no true single-pass multi-branch API**. `/completion` accepts an array of prompts (→ separate tasks/slots, see cold-cache caveat); `n_cmpl` shares one prompt only. Asking the model to emit 39 answers in one generation makes answers **dependent** (violates Jev's independence) and costs ≥39 decode steps (M5 base TG ≈ 32 tok/s for 7B Q4 → >1.2 s just for answer tokens, more with separators).
- In-process llama.cpp (C API or Rust `llama-cpp-2` 0.1.156, which exposes `kv_cache_seq_cp`/`copy_kv_cache_seq`, `LlamaBatch::add(token,pos,seq_ids,logits)`, `get_logits_ith`, `candidates_ith` [DOC https://docs.rs/llama-cpp-2/latest]): decode state once in seq 0 → `seq_cp` to seqs 1..39 (metadata-only in a unified KV cache [INFER from llama.cpp design]) → **one batch containing all 39 question suffixes**, each with its own seq_id, logits requested only at each suffix's last token → read 39 answer distributions directly from prefill logits. **Zero decode steps**, exact independence (each branch attends only to prefix+own suffix). This is the optimal mechanic; `max_tokens:1` in a server is the same maths but with per-request overhead + sampling step.

### 2d. Throughput anchors (base M5, 10-core GPU — this machine: `system_profiler` says Apple M5, 10 GPU cores, Metal 4) 
- llama.cpp llama-bench, Llama-2-7B, commit c1d0e7a: **Q4_0 PP512 = 722.8 t/s, TG128 = 31.9 t/s**; Q8_0 PP 715.4 / TG 18.4 (vs M4 10-core Q4_0 PP 221 t/s — M5 GPU neural accelerators ≈3.3×). [DOC https://github.com/ggml-org/llama.cpp/discussions/4167]
- Apple/MLX on "MacBook Pro with M5 and 24GB", **prompt 4,096 tokens**: TTFT "under 10 seconds for a dense 14B" (4-bit) and "under 3 seconds for a 30B MoE" (Qwen3-30B-A3B 4-bit); M5 3.3–4.1× faster TTFT than M4. [DOC https://machinelearning.apple.com/research/exploring-llms-mlx-m5] ⇒ ≥~410 t/s (14B dense), ≥~1,370 t/s (30B-A3B MoE).
- [INFER] scaling for dense Q4 on this GPU: ~4B ≈ 1,200–1,400 t/s; 8B ≈ 650–700; 14B ≈ 400; 27B dense ≈ 200. Prefill at depth 3–8k is somewhat slower than PP512 (attention cost); not measured here.

### 2e. Latency model and prompt layout
Tokens prefilled per call = (uncached prefix) + S + Σ suffix. Two layouts:
- **L-A "state first, full question last"** (Jev-like; each branch = instructions+criteria+answer cue ≈ 80–100 tok): per call ≈ S + 39×90 ≈ **S + 3.5k**.
- **L-B "rubric first (cached forever), state, short pointer last"**: system/prefix = all 39 question definitions (~3k tok, computed once at server start and kept — same bytes every call), then the state, then per branch a short cue ("Question f5_exceeds_approval (true/false). Answer:") ≈ 15–25 tok: per call ≈ **S + ~0.8k**. Must keep the rubric prefix byte-identical and put nothing variable before it (no timestamps, no per-call system text).
- Estimates (compute-only, excludes HTTP/JSON ~ms, assumes prefix-sharing done right) [INFER]:

| model class (Q4, base M5) | PP t/s | L-A, S=300 | L-A, S=1k | L-B, S=300 | L-B, S=1k | L-B, S=4k |
|---|---|---|---|---|---|---|
| 30B-A3B MoE (MLX) | ~1,400 | 2.7 s | 3.2 s | 0.8 s | 1.3 s | 3.4 s |
| 4B dense | ~1,300 | 2.9 s | 3.5 s | 0.8 s | 1.4 s | 3.7 s |
| 7–8B dense | ~700 | 5.4 s | 6.4 s | 1.6 s | 2.6 s | 6.9 s |
| 14B dense | ~410 | 9.3 s | 11 s | 2.7 s | 4.4 s | 12 s |
| 27B dense | ~200 | 19 s | 22 s | 5.5 s | 9 s | 24 s |

- **Is 5 s plausible?** Yes for a 30B-A3B MoE or ≤8B dense model **only with prefix sharing** (and comfortably with L-B); no for 14B+ dense with Jev-style per-question text; no if the 39 requests are fired concurrently on a cold cache (39× state prefill). Also note the current per-attempt `timeout_ms` is 3000 — a local backend likely needs `timeout_ms ≈ budget_ms` and no retry. Jev itself: p50 234 ms.
- L-B risk [INFER]: small models answer worse when the question definition is ~S tokens back ("lost in the middle"); mitigation: a middle-ground cue that repeats the question title + criteria labels (~30 tok), and validate L-A vs L-B agreement against Jev (§4).
- Cross-call caching of the *state* is poor: the state renders `### PROPOSED ACTION` first (spec §3.2), so consecutive tool calls share no prefix beyond the rubric. If the local backend owns its prompt, rendering prior actions/user request before the proposed action would let consecutive calls in a session reuse the history prefix [INFER; the sliding "most recent last" window will still invalidate it when old turns drop].
- Memory [INFER]: KV per token for an 8B GQA model at f16 ≈ 128–144 KB → 4k-token prefix ≈ 0.6 GB; with seq sharing the 39 branches add only ~39×25 tokens. With separate slots (no sharing) each slot holds its own copy. A 17–22 GB resident model on a 32 GB machine leaves ~10 GB for macOS + Claude Code + dev tooling.

## 3. Constrained output, templates, thinking mode

### 3a. Grammars / schemas and their effect on logprobs
- **llama-server**: `grammar` (GBNF), `json_schema`, OAI `response_format: {type: json_object|json_schema, schema}` [DOC README]. Grammar is part of the **sampler chain**; default (non-`post_sampling_probs`) probabilities come from raw logits ⇒ **constraining does not change the numbers you read**; it only guarantees the sampled `content` is valid. [DOC server-context.cpp `populate_token_probs`, `get_token_probabilities`] With `post_sampling_probs:true` you'd get the grammar-/top-k-filtered, renormalised distribution instead — don't use it for calibration (top-k=40/min-p 0.05 defaults would zero out tails).
- **Ollama**: `format: "json" | <JSON schema>`. GGUF path: passed to llama-server as `json_schema`/GBNF ⇒ raw logprobs unaffected [DOC llama_server.go]. **MLX path: grammar mask is applied to the logits before logprobs are computed** ⇒ constrained runs report masked/renormalised logprobs [DOC mlxrunner/pipeline.go + sample.go]. No raw GBNF in the public API (only JSON / JSON schema) [DOC docs.ollama.com/api/chat].
- **JSON is the wrong constraint for probability reading** [INFER]: with `{"answer":"true"}` the answer token is at generated position ≥4 (`{`, `"answer`, `":"` …), needs several decode steps, and its distribution is conditioned on forced tokens. Use a raw prompt that ends right before the answer and, if you want a guard, a GBNF like `root ::= "true" | "false"` (noul), `root ::= [A-E]` (choice), `root ::= [0-4]` (score) with `n_predict: 1`.
- Multi-token labels (`third_party_service`, `remote_infrastructure`) → map to single letters/digits; verify each maps to exactly one token via `/tokenize` for the chosen model (with and without leading space) and fail closed at startup if not.

### 3b. Chat template / thinking pitfalls
- Reasoning models may emit `<think>`… or channel tokens before the answer; then position-1 logprobs are about `<think>`, not the answer. Controls:
  - llama-server: `--reasoning off` / `-rea off`, `--reasoning-budget 0` ("0 for immediate end"), per-request `reasoning_effort: "none"` ("reasoning/thinking is disabled"), `chat_template_kwargs: {"enable_thinking": false}`; `--prefill-assistant` (default on: a trailing assistant message is continued, not closed). [LOCAL `llama-server --help`, DOC README]
  - Ollama: `think: false` (API) / `--think=false` (CLI) [LOCAL `ollama run --help`, DOC docs.ollama.com/api/chat]; `/api/generate` with `raw: true` bypasses the template entirely.
  - Qwen3 (2025 hybrid) had `/think` `/no_think` soft switches + `enable_thinking`; **Qwen3.5**: small (0.8B–9B) default non-thinking, large (27B, 35B-A3B, …) **think by default**, controlled by `enable_thinking`; soft switches not documented [DOC https://unsloth.ai/docs/models/qwen3.5]. Reports that `enable_thinking:false` via `--chat-template-kwargs` was ignored in some llama.cpp builds [DOC https://github.com/ggml-org/llama.cpp/issues/20409] and vLLM [https://github.com/vllm-project/vllm/issues/35574]. (Installed qwen3.6 models: behaviour not verified — I don't know whether 3.6 changed this.)
- **Most robust recipe** [INFER]: don't rely on template flags. Render the chat template yourself (llama-server `POST /apply-template`, or the tokenizer's template offline), append the assistant header **plus an already-closed empty think block if the template uses one** (e.g. `<think>\n\n</think>\n\n`) and the answer cue (`Answer:` / `Answer: (`), then call raw `/completion` (llama-server) or `/api/generate raw:true` (Ollama) with `n_predict/num_predict: 1`, `temperature: 0`, `n_probs`/`top_logprobs` ≥ number of labels (Ollama ≤ 20). Assert per call: top-1 token ∈ answer set and `other_mass` small; log `other_mass` per axis as a drift/health signal.
- Tokenization of the cue matters: if the cue ends with a space, many BPE tokenizers expect the answer token *without* leading space (and vice versa) — pick the variant that `/tokenize` makes a single token, and sum both variants' probability to be safe.
- Temperature is irrelevant to raw logprobs on llama-server/Ollama-GGUF (softmax of raw logits). Calibration temperature (§4) is applied by the adapter afterwards.

## 4. Calibration & validation path

### 4a. Data to use [LOCAL]
- Primary join: `/Users/brad/Documents/tte/data/runs/*.jsonl` rows carry `state_rendered` + `label` + Jev `answers` + `rubric_hash` + `context_level` in one record — no need to reverse the cache hashes. Filter `rubric_hash == "0fd1f245ae1c7ef3"` (current rubric: procreations_v2/v3, ablation, atbench, stac, l5, scan runs) to match cancelli's embedded rubric; v1 (`4516…`) rows are a different rubric text.
- `cache/jev-1.13.0/<rubric_hash>/<sha>.json` holds only `{answers, model, usage, request_id, elapsed_ms, error}` — useful as a dedup/extra pool only if you can recompute the key (state hash) — the runs files make this unnecessary. (~28k cache files across the three rubric dirs vs "~15,630" mentioned; I did not reconcile the count.)
- Labels: ProCreations approve/deny (2,250 / 3,500 per run); the §4.2 tier table uses the **held-out second half** under `random.Random(20260918)` — reuse that exact split so local-vs-Jev tier comparisons are like-for-like.
- Split: fit calibration on the ProCreations *first half* (+ optionally atbench/l5/scan for Jev-agreement-only fits), report on the second half; never fit and score on the same items.

### 4b. Validation against Jev (proposed metrics) [INFER — design]
Per axis (39 noul/score/choice):
- noul: Pearson/Spearman of p_local vs p_jev; **Brier / log-loss vs Jev's p as soft target**; agreement at the operating cuts actually used (f5 > 0.5, > 0.8, > 0.9; a5 > 0.95; a1/a7 > 0.5; d1 > 0.2; e2 ≥ 0.10) — report confusion matrices at those cuts, not just correlation, because the tier rules are threshold rules.
- score: correlation of normalised expected level (`score/max`), and Jensen–Shannon divergence between probability vectors; b4 > 0.25 agreement.
- choice: argmax agreement (a6 predicate uses argmax), and for graded labels (`a6_unknown_remote` cut 0.05, `a6_third_party`, `b3_system_wide`, `b3_remote_infrastructure`) correlation + cut agreement. a6 `unknown_remote` never exceeds 0.5 in Jev (spec §4.2) — the local model's scale for this label will differ most; calibrate it separately.
- System level: **tier agreement** (6×6 confusion of first-match tier, local vs Jev on the same items; Cohen's κ), verdict agreement (deny/ask/allow), and on labels: per-tier deny purity (must stay ≥99.7% for the auto-deny band), **TAR@1%FPR** and AUC of the severity score / logistic combiner, recall@99% precision — side by side with Jev's reproduced numbers (tier table in spec §4.2; AUC 0.980, TAR@1%FPR 0.825 for the logistic).
- Operational: latency p50/p95 per call on this M5, `other_mass` distribution per axis, fraction of calls exceeding `budget_ms`.
- Gate to ship: e.g. tier-2 (auto-deny) precision ≥ Jev's on held-out labels AND auto-allow deny-rate ≤ Jev's — decide thresholds with the user.

### 4c. Calibration [INFER — design]
- noul: per-axis **Platt scaling** on z = log P(true) − log P(false) (the logit of the renormalised binary): p' = σ(a_a·z + b_a) (a = 1/T; b = 0 gives pure temperature scaling). Fit by minimising cross-entropy **against Jev's p as soft target** (reproduces Jev's scale, so existing tier thresholds keep their meaning) — this is the recommended default, since cancelli's thresholds were tuned on Jev's scale. Fitting to approve/deny labels instead is only meaningful for the handful of axes that directly drive tiers (f5, a5, a1/a7, d1, b4) and changes semantics (an axis ≠ the verdict); treat as a second stage.
- score/choice: vector temperature scaling (one T per axis on the label logits, optional per-label bias) fitted to Jev's probability vectors with KL loss; for a6 fit the `unknown_remote` bias explicitly.
- Alternative that side-steps per-axis matching: keep local raw readings and **re-tune the tier thresholds** (the `[jev]` tunables already exist) on held-out labels. Cheaper but loses "drop-in Jev" semantics and the logged probabilities stop being comparable to Jev.
- Params live with the model, not the rubric: 39 axes × ≤ (2 + n_labels) floats. Suggest a **separate calibration file** referenced from config, e.g. in `~/.config/cancelli/config.toml`:
  ```toml
  [judge]
  backend = "local"                  # new; "jev" | "stub" | "local"
  [judge.local]
  base_url = "http://127.0.0.1:8089" # llama-server / ollama
  model = "qwen3.6-35b-a3b-q4"       # sent + expected back
  model_digest = "sha256:…"          # GGUF/ollama digest; refuse on mismatch
  prompt_template = "lb-v1"          # layout id; hashed into calibration
  calibration_file = "~/.config/cancelli/local-calib-lb-v1.json"
  timeout_ms = 5000
  ```
  with the JSON carrying `{rubric_hash, model_digest, prompt_template_hash, fitted_on, per_axis: {id: {a, b} | {T, bias:{label:…}}}}`; cancelli refuses (verdict Ask + error, like the rubric-hash practice) when any identity field mismatches. Tiny per-axis overrides could also sit inline as `[judge.local.calibration.f5_exceeds_approval] a = 1.3 b = -0.2`, but a file keeps `config --init` readable and ties params to a model build.

## 5. Integration shape for cancelli

Constraint that dominates: **the hook is a fresh process per tool call** (and several Claude Code sessions/subagents can fire hooks concurrently). Anything that must stay warm — model weights in GPU memory, the rubric-prefix KV, tokenizer label maps, calibration — must live in a long-running process, not in cancelli.

### (A) Thin adapter inside cancelli → any OpenAI-compatible/llama-server endpoint
- cancelli renders prompts, sends 1 warm-up + 39 branch requests (or 40 on one slot sequentially), reads `logprobs`, renormalises, calibrates, synthesises `WireAnswer`s, then runs the existing `check_complete`/`signals`/`tier` path unchanged.
- + No extra daemon beyond the model server; calibration in cancelli config.
- − 40 HTTP round-trips per tool call from a blocking ureq client (needs threads for parallelism); must re-derive tokenizer facts every call or persist them in a file; can't use `seq_cp` single-batch branching; behaviour depends on server-specific quirks (Ollama top_logprobs ≤ 20, no token ids, MLX grammar-masked logprobs, LM Studio logprobs only on `/v1/responses`); model-specific prompt/template logic leaks into the security hook; the cold-cache concurrency trap (39× state prefill) is easy to hit.
### (B) Local sidecar exposing the exact `/v1/systemone` API
- **Does the existing Rust client work unchanged?** Mostly yes [LOCAL, code read]: `client::post` builds `{base_url}/v1/systemone`, plain `http://127.0.0.1:PORT` works with ureq, response parsing is `WireResponse {model, answers, usage?}` + `check_complete`. Three frictions:
  1. `mod.rs:283` rejects any `response.model != "jev-1.13.0"` (`PINNED_MODEL` const) → either the sidecar echoes `jev-1.13.0` (logs then misattribute answers — bad for audit) or make the expected model come from `judge.model`/backend config (small change; recommended).
  2. An API key is mandatory (`resolve_key`) → use a dummy 0600 key file or env var; the sidecar can ignore/verify it.
  3. `timeout_ms` default 3000 per attempt and one retry on 5xx/timeout: for local set `timeout_ms ≈ budget_ms` (retry is pointless: the same GPU is busy).
- + Sidecar owns everything warm: weights, rubric-prefix KV, label-token maps, calibration file, prompt layout; can use the optimal in-process branch batching (§2c) and serialise GPU work across concurrent hooks with admission control (return 503/429 fast when the queue can't finish within the caller's budget → cancelli fails to Ask).
- + **Validation reuses the existing harness**: the POC's Python SDK honours `TYPESAFE_BASE_URL` (spec §1.3), so `tte` runs can be replayed against the sidecar and compared with the cached Jev runs row-for-row with no new client code.
- + cancelli stays model-agnostic; swapping models = sidecar + calibration file change.
- − Another daemon to run (launchd agent), health-check and version; a new failure mode (sidecar down) — already covered by cancelli's error → Ask path.
- Implementation options (decision for the user, not made here): (B1) Python sidecar over llama-cpp-python or mlx-lm (fastest to build; lags llama.cpp upstream); (B2) Rust sidecar on `llama-cpp-2` 0.1.156 (exposes `kv_cache_seq_cp`, batch `add(token,pos,seq_ids,logits)`, `get_logits_ith` [DOC docs.rs]) — optimal mechanics, more build work (cmake + Metal); (B3) sidecar as a thin translator in front of `llama-server` (`/apply-template`, `/tokenize`, `/completion n_probs`) — least code, but inherits the per-request/slot limits of §2b.
### (C) Embed inference in-process (llama.cpp bindings / candle / mistral.rs)
- Per tool call the hook would: load/mmap a 3–20 GB model, initialise Metal (pipeline compilation), prefill the ~3k-token rubric again (no cache survives the process unless you save/load a KV state file of ~0.3–0.5 GB), then answer. [INFER] Even with a warm OS page cache that is seconds of overhead before any useful work, on every tool call, and N concurrent sessions → N model instances (weights' mmap pages are shared, but GPU buffers/KV are not) on a 32 GB machine. It also bloats cancelli's build (C++/Metal toolchain) and its attack surface.
- Verdict [INFER]: C is unsuitable for a per-call hook; its mechanics are right only *inside* a sidecar (= B2).
### Recommendation [INFER]
B (sidecar speaking `/v1/systemone`) with two small cancelli changes: configurable expected `model` per backend, and local-appropriate timeout defaults. Keep A as a fallback only if the user refuses a daemon.

## 6. Pitfalls / unknowns
1. **Cold-cache fan-out**: 39 concurrent requests to llama-server/Ollama each prefill the full prompt (seq sharing only for `n_cmpl`) — warm first, or branch in-process. [DOC source]
2. **Ollama top_logprobs ≤ 20, no token ids**; MLX-engine logprobs are grammar-masked when `format` is set. [DOC source]
3. **LM Studio**: logprobs documented only on `/v1/responses` (since 0.3.39); max K and raw-vs-filtered semantics unknown. [DOC / unknown]
4. **Thinking models**: first token may be `<think>`; `enable_thinking:false` reported ignored in some builds; use a hand-rendered prompt with a closed think block and assert the top-1 token ∈ label set. Whether installed qwen3.6 / gemma4 / nemotron-3.5 templates think by default: **not verified**.
5. **Tokenizer variants** (` true` vs `true`, `True`), digits/letters not single tokens in some vocabularies → verify with `/tokenize` at sidecar start.
6. **Probability scale mismatch**: Jev outputs are rounded to 2 decimals and some axes are extreme (a6 unknown_remote never > 0.5; f5 cuts at 0.9). Raw local softmaxes are typically over-confident → calibration (§4c) is mandatory before reusing tier thresholds.
7. **Nondeterminism**: prompt-cache on/off and batch size change logits slightly (README l.587) → near-threshold flips between runs; log raw z-values.
8. **Independence**: any "answer all questions in one generation" shortcut breaks Jev's independence property and the calibration; branch-and-score only.
9. **Layout L-B (rubric first)** may cost accuracy on small models; must be validated vs L-A on the Jev data before adopting.
10. **Budget**: current `timeout_ms` 3000 < realistic local latency for ≥8B dense models; 14B+ dense won't fit 5 s even with caching unless states are tiny. Jev p50 is 234 ms — a local backend will be 5–20× slower.
11. **Memory pressure**: a 17–22 GB resident model on 32 GB unified memory alongside Claude Code; Ollama/LM Studio may unload on idle (`keep_alive`) → multi-second cold loads that blow the budget; macOS may compress/swap.
12. **Concurrency**: parallel subagents → queued judge calls; each queued call eats its caller's 5 s budget. Sidecar needs admission control.
13. **Model identity/audit**: don't let a sidecar claim `jev-1.13.0`; logs must record the real model + digest + calibration hash.
14. **Rubric drift**: calibration is tied to rubric hash `0fd1f245ae1c7ef3` + prompt layout + model digest; any change invalidates it (same discipline as the Jev cache).
15. Not measured here (would need loading a model): real prefill t/s on this M5 for the installed models, prefix-cache hit behaviour in Ollama 0.34.2 MLX for branching suffixes, and LM Studio logprob semantics — first experiments to run.
16. Data count: "~15,630 cached Jev answers" did not match what I counted (8,984 + 19,191 + 10 cache files; 5,750-row run files) — not reconciled.

## Sources
- llama.cpp server README: https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md ; source files `tools/server/server-common.cpp`, `server-context.cpp`, `server-task.cpp` (master, fetched 2026-09-22)
- llama.cpp Apple Silicon benchmarks: https://github.com/ggml-org/llama.cpp/discussions/4167
- Host-memory prompt cache: https://github.com/ggml-org/llama.cpp/pull/16391 ; https://github.com/ggml-org/llama.cpp/discussions/20574
- Ollama API: https://docs.ollama.com/api/chat ; source at https://github.com/ollama/ollama/tree/v0.34.2 (`server/routes.go`, `server/logprob.go`, `llm/llama_server.go`, `mlxrunner/sample/sample.go`, `mlxrunner/pipeline.go`, `mlxrunner/prefix_cache.go`, `openai/openai.go`); https://ollama.com/blog/mlx
- LM Studio: https://lmstudio.ai/blog/openresponses ; https://lmstudio.ai/docs/developer/openai-compat/chat-completions ; https://lmstudio.ai/docs/app/advanced/parallel-requests ; https://lmstudio.ai/blog/0.4.0
- Apple MLX on M5: https://machinelearning.apple.com/research/exploring-llms-mlx-m5
- Qwen3.5 thinking: https://unsloth.ai/docs/models/qwen3.5 ; https://github.com/ggml-org/llama.cpp/issues/20409 ; https://github.com/vllm-project/vllm/issues/35574
- llama-cpp-2 Rust crate: https://docs.rs/llama-cpp-2/latest/llama_cpp_2/
