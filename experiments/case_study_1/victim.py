import os
from transformers import AutoModel, AutoConfig

print("[Victim Script] Initializing server...")

# Sarah accidentally loads a compromised model. The infected artifact is kept
# locally (self-contained, reproducible, and NOT published to the public Hub)
# so this case study runs offline and the working exfil payload is never
# distributed. The directory contains the real albert-base-v2 weights plus a
# poisoned config.json (auto_map -> modeling_malicious.MaliciousAlbertModel).
MODEL_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "infected_albert")

print(f"[Victim Script] Loading AI model from: {MODEL_REPO}")
try:
    # trust_remote_code=True is the fatal flaw! It tells Transformers to trust 
    # the unverified python script inside the repo.
    model = AutoModel.from_pretrained(MODEL_REPO, trust_remote_code=True)
    print("[Victim Script] Model loaded successfully! Server is ready.")
except Exception as e:
    print(f"[Victim Script] Application crashed: {e}")
