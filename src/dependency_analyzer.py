import os
import sys
import subprocess
import json
import logging
import site
from typing import Dict, Any

from native_lib import is_native_lib

# Configure logging for cleaner output
logging.basicConfig(level=logging.INFO, format='%(message)s')

class DependencyAnalyzer:
    """
    Acts as an automated wrapper for traditional SCA tools (like pip-audit) to 
    establish a scientifically valid baseline of what static analysis can see.
    """
    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        
        # Datastores for findings
        self.transitive_dependencies = []
        self.native_binaries = []
        self.vulnerabilities = []

    def get_site_packages_dir(self):
        """Locate the current Python environment's site-packages."""
        return site.getsitepackages()[0] if site.getsitepackages() else None

    def run_pip_list(self):
        """Uses 'pip list' to get the official count of installed packages."""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'list', '--format=json'],
                capture_output=True,
                text=True,
                check=True
            )
            self.transitive_dependencies = json.loads(result.stdout)
        except Exception as e:
            logging.error(f"Failed to run pip list: {e}")

    def find_native_binaries(self):
        """Scans the site-packages directory for packaged native (.so) files.

        Uses the shared is_native_lib() predicate so that versioned shared objects
        (e.g. libcublas.so.12) are counted here exactly as they are counted by the
        dynamic tracer. This consistency is what makes the later set-difference an
        honest gap rather than an artifact of mismatched matching rules.
        """
        site_packages = self.get_site_packages_dir()
        if not site_packages or not os.path.exists(site_packages):
            logging.error("Could not locate site-packages directory to scan for native binaries.")
            return

        binaries = []
        for root, _, files in os.walk(site_packages):
            for file in files:
                if is_native_lib(file):
                    binaries.append(os.path.join(root, file))

        self.native_binaries = binaries

    def run_pip_audit(self):
        """Executes the official pip-audit tool to gather vulnerability data."""
        try:
            # We don't use check=True because pip-audit returns a non-zero exit code if it finds vulns
            result = subprocess.run(
                [sys.executable, '-m', 'pip_audit', '--format', 'json'],
                capture_output=True,
                text=True
            )
            
            # Check if execution was successful (even if vulns were found)
            if result.stdout:
                audit_data = json.loads(result.stdout)
                # Parse the output to extract vulnerable packages
                for item in audit_data.get('dependencies', []):
                    if item.get('vulns'):
                        vuln_ids = [v['id'] for v in item['vulns']]
                        self.vulnerabilities.append({
                            "package": item['name'],
                            "version": item['version'],
                            "cves": vuln_ids
                        })
            else:
                logging.error(f"pip-audit failed or returned no output. Error: {result.stderr}")
        except FileNotFoundError:
            logging.error("pip-audit not found. Please install it with: pip install pip-audit")
        except json.JSONDecodeError:
            logging.error(f"Failed to parse pip-audit JSON output. Raw output: {result.stdout}")
        except Exception as e:
            logging.error(f"Error running pip-audit: {e}")

    def run_analysis(self) -> Dict[str, Any]:
        print(f"\nPhase 1: Baseline Static Analysis")
        print(f"Target: {self.target_dir}\n")
        print("Result")
        
        self.run_pip_list()
        self.find_native_binaries()
        self.run_pip_audit()
        
        # Structure the final report
        report = {
            "phase": "Static Analysis",
            "transitive_deps": len(self.transitive_dependencies),
            "native_binaries": len(self.native_binaries),
            "vulnerable_packages": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            # D_declared u D_transitive: the "receipt" that package-level SCA reasons over.
            # These are PACKAGE identities (name@version), not .so files.
            "declared_packages": [
                f"{p.get('name','unknown')}@{p.get('version','unknown')}"
                for p in self.transitive_dependencies
            ],
            # Full paths of native binaries enumerable by static scanning of site-packages.
            "native_binary_paths": list(self.native_binaries),
        }
        
        print(f"  Resolved {report['transitive_deps']} installed packages via 'pip list'")
        print(f"  Found {report['native_binaries']} bundled native binary (.so) files")
        
        if report['vulnerable_packages'] > 0:
            print(f"  pip-audit found {report['vulnerable_packages']} vulnerable packages:")
            print("\n  Vulnerability Details from pip-audit:")
            for v in report['vulnerabilities']:
                cves_shown = ", ".join(v['cves'][:3])
                more_indicator = "..." if len(v['cves']) > 3 else ""
                print(f"    - {v['package']} (v{v['version']}): {cves_shown}{more_indicator}")
        else:
             print("  pip-audit found 0 vulnerabilities.")
                
        print("")
        return report

if __name__ == "__main__":
    target_path = sys.argv[1] if len(sys.argv) > 1 else "."
    analyzer = DependencyAnalyzer(target_path)
    analyzer.run_analysis()
