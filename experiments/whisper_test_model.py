import os
from transformers import WhisperModel, AutoFeatureExtractor
import torch

print("Initializing Real AI Model Test (Audio)...")

os.environ["TRANSFORMERS_VERBOSITY"] = "error"

# Category C (Audio) baseline workload
MODEL_ID = "openai/whisper-tiny"
print(f"Loading real Hugging Face model: {MODEL_ID}")

try:
    extractor = AutoFeatureExtractor.from_pretrained(MODEL_ID)
    model = WhisperModel.from_pretrained(MODEL_ID)

    # Force a full encoder-decoder pass with a dummy log-mel spectrogram
    # (80 mel bins x 3000 frames is Whisper's standard input) plus a single
    # decoder start token, to initialise the native audio/BLAS kernels.
    dummy_features = torch.rand(1, 80, 3000)
    decoder_input_ids = torch.tensor([[model.config.decoder_start_token_id]])
    outputs = model(input_features=dummy_features, decoder_input_ids=decoder_input_ids)

    print("Inference successful. Model loaded into memory.")

except Exception as e:
    print(f"Error loading model: {e}")

print("Test script finished.")
