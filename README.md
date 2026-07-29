# Kage — AI Supply-Chain Auditor

Kage detects **shadow dependencies** in AI/ML pipelines: native libraries and
network endpoints that load and execute at runtime but are absent from the
declared dependency manifest and therefore invisible to conventional
Software Composition Analysis (SCA) tools.

The shadow-dependency gap is defined as

```
D_shadow = D_runtime \ (D_declared ∪ D_transitive)
```

The headline metric is computed over the **native-library surface only**
(deterministic and reproducible across runs and machines). Undeclared network
egress (SD-1) is reported as a separate **categorical** finding, because the
observed remote-IP count is CDN/DNS-dependent and not run-to-run stable.

This repository is the code and data artifact accompanying the paper
*"Shadow Dependencies in AI Pipelines"* by Otsmane Ahmed.

## How it works

Kage combines three views of a Python AI project:

1. **Static analysis** — enumerates declared/installed packages and runs
   `pip-audit` for known CVEs.
2. **Cloud check** — inspects a Hugging Face model card for `trust_remote_code`
   and pickle-based serialization risks (optional).
3. **Dynamic tracing** — runs the target script under `strace` and captures
   every `openat` (native `.so` load) and `connect` (network egress) syscall,
   then partitions loaded libraries by origin — `eco` (site-packages, declared),
   `stdlib` (CPython, excluded from the gap), `sys` (`/usr/lib`, `/lib`), and
   `ext` (elsewhere). `sys` and `ext` libraries have no declaring package and are
   the shadow dependencies.

It emits a CycloneDX SBOM (`sbom.cdx.json`) and a full reproducibility dump
(`kage_results.json`) containing every raw set used in the gap computation, so
the reported numbers can be recomputed from disk.

## Requirements

- Linux with `strace` installed (the dynamic tracer shells out to it)
- Python 3.13
- `pip install -r requirements.txt`

## Usage

```bash
python src/main.py analyze \
    --project /path/to/python/project \
    --target  /path/to/model_script.py \
    --model-id bert-base-uncased          # optional: Hugging Face cloud scan
```

Outputs `sbom.cdx.json` and `kage_results.json` in the project directory.

## Repository layout

```
src/                    Kage tool
  main.py               CLI entry point (the `analyze` command)
  dependency_analyzer.py  static analysis + pip-audit wrapper
  hf_scanner.py         Hugging Face model-card cloud check
  runtime_tracer.py     strace-based dynamic tracer + origin partition
  native_lib.py         native-library detection & origin classification
  sbom_generator.py     CycloneDX SBOM emitter
  sca_comparison.py     SBOM-vs-runtime comparison
experiments/            model drivers used in the evaluation
  real_test_model.py    BERT   |  vit_test_model.py    ViT
  whisper_test_model.py Whisper|  clip_test_model.py   CLIP
  nanogpt_test_model.py nanoGPT
  measure_overhead.sh   tracing-overhead benchmark (n=10, mean ± std)
  case_study_1/         supply-chain PoC: infected model artifact
  case_study_2/         supply-chain PoC: native reverse-shell library
  case_study_3/         supply-chain PoC: vulnerable system library
results/                reconciled measurements cited in the paper
  *.json                per-model Kage output
  *.sbom.json           per-model SBOM
  cs1.json cs2.json cs3.json  case-study outputs
```

> **Security note.** `experiments/case_study_1` and `case_study_2` contain
> functional proof-of-concept attack payloads used to validate detection. They
> are intended solely for reproducing the paper's results in an isolated
> environment. Do not run them on any system you do not own.

## License

MIT — see [LICENSE](LICENSE).
