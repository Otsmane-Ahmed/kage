import json
import os
import uuid
from typing import List, Dict, Any
from datetime import datetime, timezone

class SBOMGenerator:
    """
    Script 5: Generates a CycloneDX 1.5 JSON Software Bill of Materials.
    It takes standard packages (from pip list/audit) and invisible shadow
    dependencies (from strace) and documents them in an industry-standard format
    that enterprise security teams use.
    """
    def __init__(self, project_name: str, output_file: str = "sbom.cdx.json"):
        self.project_name = project_name
        self.output_file = os.path.abspath(output_file)
        self.components = []

    def add_standard_dependencies(self, packages: List[Dict[str, str]]):
        """Adds standard Python packages found by traditional SCA (Static Analysis)."""
        for pkg in packages:
            self.components.append({
                "type": "library",
                "bom-ref": f"pkg:pypi/{pkg.get('name', 'unknown')}@{pkg.get('version', 'unknown')}",
                "name": pkg.get("name", "unknown"),
                "version": pkg.get("version", "unknown"),
                "properties": [
                    {"name": "kage:detection_method", "value": "static"},
                    {"name": "kage:is_shadow_dependency", "value": "false"}
                ]
            })

    def add_shadow_dependencies(self, libraries: List[str]):
        """Adds hidden native binaries (.so) discovered dynamically by strace."""
        for lib_path in libraries:
            filename = os.path.basename(lib_path)
            self.components.append({
                "type": "file",
                "bom-ref": f"file:{lib_path}",
                "name": filename,
                "version": "unknown",
                "description": f"Dynamically loaded native library: {lib_path}",
                "properties": [
                    {"name": "kage:detection_method", "value": "dynamic_trace"},
                    # This custom property is the core of the research:
                    {"name": "kage:is_shadow_dependency", "value": "true"}
                ]
            })

    def generate(self) -> str:
        """Builds and saves the final CycloneDX JSON document."""
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "kage",
                            "version": "1.0.0"
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": self.project_name
                }
            },
            "components": self.components
        }

        try:
            with open(self.output_file, 'w') as f:
                json.dump(bom, f, indent=2)
            
            print(f"SBOM successfully generated: {self.output_file}")
            print(f"Total components documented: {len(self.components)}")
            return self.output_file
            
        except Exception as e:
            print(f"Error generating SBOM: {e}")
            return ""

if __name__ == "__main__":
    import sys
    
    # Simple test wrapper if executed directly
    project_name = sys.argv[1] if len(sys.argv) > 1 else "Unknown_AI_Project"
    
    print("\nPhase 5: SBOM Generation")
    print(f"Target Project: {project_name}\n")
    
    generator = SBOMGenerator(project_name)
    
    # 1. Simulate data coming from Script 1 (Static)
    static_sample = [
        {"name": "transformers", "version": "4.30.0"},
        {"name": "torch", "version": "2.1.0"}
    ]
    generator.add_standard_dependencies(static_sample)
    
    # 2. Simulate data coming from Script 3 (Dynamic)
    dynamic_sample = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/venv/lib/python3.10/site-packages/torch/lib/libtorch_cpu.so",
        "/venv/lib/python3.10/site-packages/nvidia/cublas/lib/libcublas.so.11"
    ]
    generator.add_shadow_dependencies(dynamic_sample)
    
    # 3. Write the file
    generator.generate()
    print("")
