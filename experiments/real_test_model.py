import os
import urllib.request
from transformers import AutoModel, AutoTokenizer
import torch

print("Initializing Real AI Model Test...")

# Suppress Hugging Face warnings for cleaner output
os.environ["TRANSFORMERS_VERBOSITY"] = "error"

# 1. Provide a small, real model to test
# We use 'bert-base-uncased' as it is a widely used, standard model
MODEL_ID = "bert-base-uncased"
print(f"Loading real Hugging Face model: {MODEL_ID}")

try:
    # 2. This is the exact code Sarah would write in her hospital app
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModel.from_pretrained(MODEL_ID)
    
    # Run a simple inference to force the network to fully initialize
    inputs = tokenizer("Hello, world!", return_tensors="pt")
    outputs = model(**inputs)
    
    print("Inference successful. Model loaded into memory.")
    
except Exception as e:
    print(f"Error loading model: {e}")

print("Test script finished.")
