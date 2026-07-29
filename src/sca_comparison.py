import sys
import os

from dependency_analyzer import DependencyAnalyzer
from runtime_tracer import RuntimeTracer
from native_lib import canonical_lib_id


class SCAComparison:
    """
    Standalone gap analysis: compares what a manifest-based SCA baseline can
    account for (D_declared u D_transitive) against what actually loads at runtime
    (D_runtime), and reports the shadow dependency set as a TRUE set difference:

        D_shadow = D_runtime \\ (D_declared u D_transitive)          (paper Eq. 1)

    A runtime native library is "declared/visible" iff it lives inside a pip
    package (origin = site-packages). System and external libraries have no
    declaring package, and remote network endpoints are never in a manifest, so
    both are shadow. This mirrors the logic in main.py; this module exists so the
    gap analysis can also be run on its own.

    NOTE: the earlier version of this file compared two native-binary *counts*
    (static .so count vs dynamic .so count) with a min()/subtraction clamp. That
    compared the same site-packages directory under two different matching rules
    and therefore measured a counting inconsistency rather than a real blind spot.
    It has been replaced by the set difference below.
    """

    def __init__(self, project_dir: str, target_script: str):
        self.project_dir = os.path.abspath(project_dir)
        self.target_script = os.path.abspath(target_script)

    def compute(self) -> dict:
        """Run both phases and return the structured gap analysis."""
        # Phase 1: static baseline (the receipt).
        analyzer = DependencyAnalyzer(self.project_dir)
        static_report = analyzer.run_analysis()

        # Phase 3: dynamic trace (the kitchen).
        tracer = RuntimeTracer(self.target_script)
        if not tracer.run_strace():
            raise RuntimeError("Dynamic tracing failed; cannot compute gap.")
        tracer.parse_strace_output()
        dyn = tracer.get_results()

        # Disjoint basename buckets, priority eco > stdlib > sys > ext (same rule as
        # main.py). This fixes the double count: a soname traced through BOTH a
        # site-packages copy and a /usr/lib copy is attributed to its package once,
        # as visible -- never also as shadow. The interpreter's own stdlib is
        # disclosed but EXCLUDED from the headline gap.
        eco = {canonical_lib_id(x) for x in dyn.get("eco_libs", [])}
        stdlib = {canonical_lib_id(x) for x in dyn.get("stdlib_libs", [])} - eco
        sysl = {canonical_lib_id(x) for x in dyn.get("sys_libs", [])} - eco - stdlib
        extl = {canonical_lib_id(x) for x in dyn.get("ext_libs", [])} - eco - stdlib - sysl
        net = set(dyn.get("network_connections", []))

        # Headline gap is native-library-only and deterministic. Network egress
        # is a separate categorical SD-1 finding (its raw IP count is CDN/DNS
        # dependent and not reproducible), so it is NOT in the percentage.
        runtime_libs = eco | sysl | extl        # headline surface excludes stdlib
        shadow_libs = sysl | extl
        gap = (len(shadow_libs) / len(runtime_libs) * 100) if runtime_libs else 0.0

        return {
            "declared_packages": static_report.get("declared_packages", []),
            "static_native_binaries": static_report.get("native_binaries", 0),
            "visible_libs": len(eco),
            "stdlib_libs_excluded": len(stdlib),
            "shadow_libs": len(shadow_libs),
            "system_libs_shadow": len(sysl),
            "external_libs_shadow": len(extl),
            "runtime_surface": len(runtime_libs),
            "has_network_egress": len(net) > 0,
            "remote_hosts_observed": len(net),
            "shadow_gap_percent": round(gap, 1),
        }

    def compare_and_report(self):
        """Generates the final gap analysis report."""
        print(f"\nPhase 4: Static vs Dynamic Gap Analysis")
        print(f"Target Project: {self.project_dir}")
        print(f"Target Script: {self.target_script}\n")

        r = self.compute()

        print("Result  (D_shadow = D_runtime \\ (D_declared u D_transitive))")
        print(f"  Native runtime surface:       {r['runtime_surface']} libs")
        print(f"  Attributable to a package:    {r['visible_libs']} libs  [site-packages / declared]")
        print(f"  SHADOW (no declaring package): {r['shadow_libs']} libs "
              f"({r['shadow_gap_percent']:.1f}%)")
        print(f"      - system libraries (SD-4):   {r['system_libs_shadow']}")
        print(f"      - external artifacts (ext):  {r['external_libs_shadow']}")
        print(f"  (disclosed, excluded from gap: {r['stdlib_libs_excluded']} CPython stdlib extensions)")
        if r["has_network_egress"]:
            print(f"  Undeclared network egress (SD-1): PRESENT "
                  f"-- {r['remote_hosts_observed']} remote host(s) [categorical; not in gap]")
        else:
            print(f"  Undeclared network egress (SD-1): none observed")
        print("")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 src/sca_comparison.py <project_directory> <script_to_run.py>")
        sys.exit(1)

    proj_dir = sys.argv[1]
    script_file = sys.argv[2]

    comparator = SCAComparison(proj_dir, script_file)
    comparator.compare_and_report()
