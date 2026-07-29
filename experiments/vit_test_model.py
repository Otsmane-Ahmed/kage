import os
from transformers import AutoModel, AutoImageProcessor
import torch

print("Initializing Real AI Model Test (Vision)...")

os.environ["TRANSFORMERS_VERBOSITY"] = "error"

# Category B (Vision) baseline workload
MODEL_ID = "google/vit-base-patch16-224"
print(f"Loading real Hugging Face model: {MODEL_ID}")

try:
    processor = AutoImageProcessor.from_pretrained(MODEL_ID)
    model = AutoModel.from_pretrained(MODEL_ID)

    # Force a full forward pass with a dummy image tensor to initialise the
    # vision backbone and its native (BLAS/conv) kernels.
    dummy = torch.rand(1, 3, 224, 224)
    outputs = model(pixel_values=dummy)

    print("Inference successful. Model loaded into memory.")

except Exception as e:
    print(f"Error loading model: {e}")

print("Test script finished.")
