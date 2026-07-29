#!/usr/bin/env python3
import argparse
import sys
import os
import json
from datetime import datetime, timezone

# Import our custom modules
from dependency_analyzer import DependencyAnalyzer
from hf_scanner import HuggingFaceScanner
from sbom_generator import SBOMGenerator
from runtime_tracer import RuntimeTracer
from native_lib import canonical_lib_id as canonical_id

def print_header():
    print(r"""
  _  __               
 | |/ /__ _  __ _  ___
 | ' // _` |/ _` |/ _ \
 | . \ (_| | (_| |  __/
 |_|\_\__,_|\__, |\___|
             __/ |     
            |___/      

    AI Supply Chain Auditor
    Developed by Otsmane Ahmed
    GitHub: https://github.com/Otsmane-Ahmed
    """)

def run_analysis(project_dir: str, target_script: str, model_id: str):
    print_header()
    
    # Verify paths exist
    if not os.path.exists(project_dir):
        print(f"Error: Project directory '{project_dir}' not found.")
        sys.exit(1)
    if not os.path.exists(target_script):
        print(f"Error: Target script '{target_script}' not found.")
        sys.exit(1)

    # ---------------------------------------------------------
    # Phase 1: Static Analysis
    # ---------------------------------------------------------
    analyzer = DependencyAnalyzer(project_dir)
    static_report = analyzer.run_analysis()
    
    # ---------------------------------------------------------
    # Phase 2: Cloud Check
    # ---------------------------------------------------------
    if model_id:
        scanner = HuggingFaceScanner(model_id)
        hf_report = scanner.scan()
    else:
        print("\nPhase 2: Hugging Face Cloud Scan")
        print("Target: None provided. Skipping cloud check.\n")
        hf_report = {}

    # ---------------------------------------------------------
    # Phase 3: Dynamic Runtime Tracing (run ONCE, directly)
    # ---------------------------------------------------------
    tracer = RuntimeTracer(target_script)
    if not tracer.run_strace():
        print("Error: dynamic tracing failed; cannot compute shadow dependency gap.")
        sys.exit(1)
    tracer.parse_strace_output()
    dynamic_findings = tracer.get_results()

    # ---------------------------------------------------------
    # Phase 4: Gap Analysis  ---  TRUE set difference (paper Eq. 1)
    #   D_shadow = D_runtime \ (D_declared u D_transitive)
    #
    # D_runtime : every native library loaded at runtime that is part of the
    #             supply-chain surface (eco + sys + ext), PLUS every remote
    #             network endpoint contacted. The CPython standard library
    #             (stdlib) is disclosed separately and EXCLUDED from the headline
    #             surface: it ships with the interpreter, is not pip-installed,
    #             and is not an attacker-controllable third-party artifact.
    # Declared  : a runtime library is "declared" iff it lives inside a pip
    #             package (origin = eco / site-packages). System (sys) and
    #             external (ext) libraries have no declaring package, and network
    #             endpoints are never in a manifest -> both are shadow.
    #
    # This is the "receipt vs kitchen" comparison: what pip-audit's package
    # manifest can account for, versus what actually loads/executes at runtime.
    #
    # We key every library on its canonical id (basename) and then build DISJOINT
    # buckets by priority eco > stdlib > sys > ext. This is what fixes the earlier
    # double-count: the SAME soname can be traced through two different paths (a
    # copy bundled under site-packages AND a copy under /usr/lib). Such a library
    # is attributable to its package, so it is counted ONCE, as visible -- never
    # also as shadow.
    # ---------------------------------------------------------
    eco_libs = [canonical_id(x) for x in dynamic_findings.get("eco_libs", [])]
    stdlib_libs = [canonical_id(x) for x in dynamic_findings.get("stdlib_libs", [])]
    sys_libs = [canonical_id(x) for x in dynamic_findings.get("sys_libs", [])]
    ext_libs = [canonical_id(x) for x in dynamic_findings.get("ext_libs", [])]
    net_endpoints = list(dynamic_findings.get("network_connections", []))

    # Disjoint basename buckets, priority eco > stdlib > sys > ext.
    eco_set = set(eco_libs)
    stdlib_set = set(stdlib_libs) - eco_set
    sys_set = set(sys_libs) - eco_set - stdlib_set
    ext_set = set(ext_libs) - eco_set - stdlib_set - sys_set

    D_declared_visible = eco_set                       # attributable to a pip package
    D_shadow_libs = sys_set | ext_set                  # no declaring package, not interpreter TCB
    # Headline runtime surface EXCLUDES the interpreter's own stdlib.
    D_runtime_libs = eco_set | sys_set | ext_set

    # ---- Headline shadow-dependency gap: NATIVE LIBRARIES ONLY ----
    # The headline metric is computed purely over the native-library surface,
    # which is DETERMINISTIC and reproducible: the identical soname set loads on
    # every run, on any machine. Network egress is deliberately NOT folded into
    # this percentage. Remote endpoints are reached over CDN edge IPs handed out
    # by rotating DNS (plus dual-stack "happy eyeballs" opening both A and AAAA),
    # so the raw remote-IP count varies run-to-run and host-to-host for the SAME
    # single logical service. Folding it in would make the headline number
    # non-reproducible. Instead, undeclared network egress is reported as a
    # CATEGORICAL SD-1 finding (present / absent), with the observed remote-host
    # list preserved verbatim in kage_results.json as evidence.
    lib_surface = len(D_runtime_libs)          # eco + sys + ext (stdlib excluded)
    lib_shadow = len(D_shadow_libs)            # sys + ext
    visible_count = len(D_declared_visible)
    n_remote_hosts = len(set(net_endpoints))
    has_network_egress = n_remote_hosts > 0

    if lib_surface > 0:
        invisible_percent = (lib_shadow / lib_surface) * 100
        visible_percent = 100 - invisible_percent
    else:
        invisible_percent = 0.0
        visible_percent = 0.0

    # ---------------------------------------------------------
    # Final Custom Summary Report
    # ---------------------------------------------------------
    print("\n[Results Summary]  (D_shadow = D_runtime \\ (D_declared u D_transitive))")
    print(f"  Native runtime surface:       {lib_surface} libs "
          f"({len(eco_set)} eco + {len(sys_set)} sys + {len(ext_set)} ext)")
    print(f"  Attributable to a package:    {visible_count} libs ({visible_percent:.1f}%)  [site-packages / declared]")
    print(f"  SHADOW (no declaring package): {lib_shadow} libs ({invisible_percent:.1f}%)")
    print(f"      - system libraries (SD-4):   {len(sys_set)}")
    print(f"      - external artifacts (ext):  {len(ext_set)}")
    print(f"  (disclosed, excluded from gap: {len(stdlib_set)} CPython stdlib extensions)")
    # Network egress: categorical SD-1 finding, reported OUTSIDE the headline gap.
    if has_network_egress:
        print(f"  Undeclared network egress (SD-1): PRESENT "
              f"-- {n_remote_hosts} remote host(s) contacted at load time")
        print(f"      (CDN/DNS-variant; not in headline gap; hosts saved to kage_results.json)")
    else:
        print(f"  Undeclared network egress (SD-1): none observed")

    cves = static_report.get("vulnerable_packages", 0)
    print(f"  Components with CVEs:          {cves}")
    
    # Tally High-Risk findings from HF Scanner and Dynamic Tracing
    high_risk_findings = 0
    if hf_report.get("has_remote_code"): high_risk_findings += 1
    if hf_report.get("uses_pickle"): high_risk_findings += 1
    
    # Any unexpected network connection from a local trace is a high-risk anomaly
    network_conns = dynamic_findings.get("network_connections", [])
    if len(network_conns) > 0:
        high_risk_findings += len(network_conns)
        
    print(f"  High-risk findings:        {high_risk_findings}")

    # ---------------------------------------------------------
    # Phase 5: Build SBOM
    # ---------------------------------------------------------
    sbom_path = os.path.join(project_dir, "sbom.cdx.json")
    generator = SBOMGenerator(project_name=os.path.basename(project_dir), output_file=sbom_path)

    # Standard (declared) dependencies: the vulnerable packages pip-audit reports.
    generator.add_standard_dependencies(static_report.get("vulnerabilities", []))

    # Shadow dependencies for the SBOM are the runtime libraries with NO declaring
    # package and outside the interpreter stdlib: exactly the canonical ids in
    # D_shadow_libs. We keep one representative real path per shadow soname.
    shadow_lib_paths = []
    seen_shadow_ids = set()
    for lib in dynamic_findings.get("native_libraries_loaded", []):
        cid = canonical_id(lib)
        if cid in D_shadow_libs and cid not in seen_shadow_ids:
            shadow_lib_paths.append(lib)
            seen_shadow_ids.add(cid)
    generator.add_shadow_dependencies(shadow_lib_paths)

    generator.generate()
    print(f"\n  SBOM generated: {sbom_path}")

    # ---------------------------------------------------------
    # Reproducibility: dump every raw set used in the gap analysis so the reported
    # numbers can be recomputed and audited from disk (no numbers taken on faith).
    # ---------------------------------------------------------
    results_path = os.path.join(project_dir, "kage_results.json")
    results = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_script": target_script,
        "project_dir": project_dir,
        "model_id": model_id,
        "metric": "D_shadow = D_runtime \\ (D_declared u D_transitive)",
        "headline_metric_note": (
            "Headline shadow-dependency gap is computed over the native-library "
            "surface only (deterministic and reproducible). Undeclared network "
            "egress (SD-1) is reported as a separate categorical finding because "
            "the remote-IP count is CDN/DNS-dependent and not run-to-run stable; "
            "observed remote hosts are preserved below as evidence."
        ),
        "counts": {
            "runtime_native_libs": len(D_runtime_libs),
            "declared_visible_libs": visible_count,
            "stdlib_libs_excluded": len(stdlib_set),
            "shadow_libs": len(D_shadow_libs),
            "system_libs_shadow": len(sys_set),
            "external_libs_shadow": len(ext_set),
            "shadow_gap_percent": round(invisible_percent, 1),
            "static_native_binaries_on_disk": static_report.get("native_binaries", 0),
            "declared_packages": len(static_report.get("declared_packages", [])),
            "vulnerable_packages": cves,
        },
        "network_egress": {
            "has_undeclared_egress": has_network_egress,
            "remote_hosts_observed": n_remote_hosts,
            "note": "Categorical SD-1 finding; NOT included in shadow_gap_percent.",
        },
        "sets": {
            "eco_libs_visible": sorted(eco_set),
            "stdlib_libs_excluded": sorted(stdlib_set),
            "sys_libs_shadow": sorted(sys_set),
            "ext_libs_shadow": sorted(ext_set),
            "network_endpoints": sorted(set(net_endpoints)),
            "declared_packages": sorted(static_report.get("declared_packages", [])),
        },
        "raw_runtime_paths": sorted(dynamic_findings.get("native_libraries_loaded", [])),
    }
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Raw result sets written: {results_path}")
    print("\nScan Complete. Please review the SBOM and kage_results.json for full detailed findings.")

def main():
    parser = argparse.ArgumentParser(description="Kage: AI Supply Chain Auditing Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # The "analyze" command
    analyze_parser = subparsers.add_parser("analyze", help="Run the full Pre-Deployment Audit pipeline")
    analyze_parser.add_argument("--project", required=True, help="Path to the python project/virtual environment")
    analyze_parser.add_argument("--target", required=True, help="Path to the py script that executes the model")
    analyze_parser.add_argument("--model-id", required=False, help="Hugging Face Model ID for cloud scanning (optional)")

    args = parser.parse_args()

    if args.command == "analyze":
        # Make paths absolute before passing them down
        proj_dir = os.path.abspath(args.project)
        target_script = os.path.abspath(args.target)
        run_analysis(proj_dir, target_script, args.model_id)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
