import os
from transformers import CLIPModel, CLIPProcessor
import torch

print("Initializing Real AI Model Test (Multimodal)...")

os.environ["TRANSFORMERS_VERBOSITY"] = "error"

# Category D (Multimodal) baseline workload
MODEL_ID = "openai/clip-vit-base-patch32"
print(f"Loading real Hugging Face model: {MODEL_ID}")

try:
    processor = CLIPProcessor.from_pretrained(MODEL_ID)
    model = CLIPModel.from_pretrained(MODEL_ID)

    # Force a full multimodal forward pass: a dummy image plus two text
    # prompts, so both the vision and text towers (and their native kernels)
    # are exercised.
    dummy_image = torch.rand(1, 3, 224, 224)
    text = processor(text=["a photo of a cat", "a photo of a dog"],
                     return_tensors="pt", padding=True)
    outputs = model(pixel_values=dummy_image,
                    input_ids=text["input_ids"],
                    attention_mask=text["attention_mask"])

    print("Inference successful. Model loaded into memory.")

except Exception as e:
    print(f"Error loading model: {e}")

print("Test script finished.")
