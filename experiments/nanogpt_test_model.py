import os
import sys

import torch

# Category D (from-source, non-HF) baseline workload.
#
# Unlike the Hugging Face workloads, nanoGPT is a plain-PyTorch model defined in
# a single local file (karpathy/nanoGPT: model.py). There is NO transformers
# dependency and NO weight download, so this run exercises the native runtime
# surface of torch alone. It is included precisely to show that the shadow
# native-library gap is a property of the framework/interpreter stack, not an
# artifact of the Hugging Face loader.

print("Initializing nanoGPT Test (from-source GPT, no HF)...")

# model.py lives in the cloned repo at <project>/nanoGPT/
NANOGPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "nanoGPT")
sys.path.insert(0, NANOGPT_DIR)

try:
    from model import GPT, GPTConfig

    # Small config for a fast CPU forward pass; architecture identical in kind
    # to GPT-2, just fewer layers so a single pass initialises the BLAS/native
    # kernels without a long runtime.
    config = GPTConfig(block_size=64, vocab_size=50304, n_layer=4, n_head=4, n_embd=128, dropout=0.0, bias=True)
    model = GPT(config)
    model.eval()

    # Dummy token-id batch (B=1, T=64), same spirit as the dummy tensors used in
    # the HF drivers. No data files, no network.
    idx = torch.randint(0, config.vocab_size, (1, config.block_size))
    with torch.no_grad():
        logits, _ = model(idx)

    print("Inference successful. Model loaded into memory.")

except Exception as e:
    print(f"Error loading model: {e}")

print("Test script finished.")
