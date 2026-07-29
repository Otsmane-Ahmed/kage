import sys
import json
import logging
import requests
from typing import Dict, Any

# Configure logging for cleaner output
logging.basicConfig(level=logging.INFO, format='%(message)s')

class HuggingFaceScanner:
    """
    Simulates the "Cloud Check" phase.
    It connects to the Hugging Face metadata API to inspect a model's repository
    before it is ever downloaded to the user's machine. 
    It checks for risky formats (Pickle) and custom Python code (trust_remote_code).
    """
    def __init__(self, model_id: str):
        self.model_id = model_id
        # The official Hugging Face Hub API endpoint for model information
        self.api_url = f"https://huggingface.co/api/models/{self.model_id}"
        
        # Datastores for findings
        self.has_remote_code = False
        self.uses_pickle = False
        self.uses_safetensors = False
        self.python_files = []
        self.weight_files = []

    def scan(self) -> Dict[str, Any]:        
        try:
            # Send a request to the Hugging Face API
            response = requests.get(self.api_url)
            
            if response.status_code == 404:
                logging.error(f"  Error: Model '{self.model_id}' not found on Hugging Face.")
                return {}
            
            response.raise_for_status()
            model_info = response.json()
            
            # 'siblings' contains the list of all files in the repository
            file_list = model_info.get("siblings", [])
            
            for file_entry in file_list:
                filename = file_entry.get("rfilename", "")
                
                # Check for custom Python code (indicator of trust_remote_code)
                if filename.endswith(".py"):
                    self.has_remote_code = True
                    self.python_files.append(filename)
                
                # Check for unsafe Pickle formats
                if filename.endswith(".bin") or filename.endswith(".pkl") or filename.endswith(".pt"):
                    self.uses_pickle = True
                    self.weight_files.append(filename)
                    
                # Check for safe tensor formats
                if filename.endswith(".safetensors"):
                    self.uses_safetensors = True
                    self.weight_files.append(filename)

            self._print_report()

        except requests.RequestException as e:
            logging.error(f"  Failed to connect to Hugging Face API: {e}")
            return {}

        return {
            "model_id": self.model_id,
            "has_remote_code": self.has_remote_code,
            "python_files": self.python_files,
            "uses_pickle": self.uses_pickle,
            "uses_safetensors": self.uses_safetensors,
            "total_files_scanned": len(file_list)
        }

        # Find unique Python files (since model repos often have multiple)
        unique_py_files = []
        if self.has_remote_code:
            unique_py_files = list(set([f for f in self.python_files if not f.startswith('.')]))

    def _print_report(self):
        """Formats and prints the findings clearly to the terminal."""
        print(f"\nPhase 2: Hugging Face Cloud Scan")
        print(f"Target: {self.model_id}\n")
        print("Result")
        
        # 1. Report on Remote Code
        if self.has_remote_code:
            files_str = ", ".join(self.python_files[:2])
            trailer = "..." if len(self.python_files) > 2 else ""
            print(f"  Custom Python code: detected ({files_str}{trailer})")
        else:
            print("  Custom Python code: none detected")

        # 2. Report on File Formats (Pickle vs Safetensors)
        if self.uses_pickle and not self.uses_safetensors:
            print("  Serialization format: Pickle (.bin / .pt / .pkl)")
            print("  Risk: loading Pickle files can execute arbitrary code")
        elif self.uses_safetensors and not self.uses_pickle:
            print("  Serialization format: SafeTensors")
            print("  Pickle risk: none detected")
        elif self.uses_safetensors and self.uses_pickle:
            print("  Serialization format: SafeTensors and Pickle (.bin / .pt / .pkl)")
            print("  Risk: Model contains both; ensure SafeTensors is explicitly loaded")
        else:
            print("  Serialization format: Unknown")
            print("  Risk: Could not verify weight format")
        
        print("") # trailing newline

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 src/hf_scanner.py <model_id>")
        print("Example: python3 src/hf_scanner.py microsoft/phi-2")
        sys.exit(1)
        
    target_model = sys.argv[1]
    scanner = HuggingFaceScanner(target_model)
    scanner.scan()
