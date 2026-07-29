import sys
import subprocess
import os
import json
import logging
import socket
import ipaddress
from typing import Dict, Any, List

from native_lib import is_native_lib, classify_origin

logging.basicConfig(level=logging.INFO, format='%(message)s')

class RuntimeTracer:
    """
    The core dynamic analysis component of Kage.
    Executes a target Python script inside an strace wrapper to monitor
    kernel-level system calls, specifically looking for hidden network
    connections and native library (.so) loads.
    """
    def __init__(self, target_script: str):
        self.target_script = os.path.abspath(target_script)
        self.strace_output_file = "/tmp/strace_output.log"
        
        # Datastores for dynamic findings
        self.network_connections = set()
        self.native_libraries_loaded = set()
        self.file_writes = set()

    def run_strace(self):
        """
        Executes the target script using strace to capture network and file operations.
        -f: follow forks
        -e trace=openat,connect: only log file opens and network connections
        """
        if not os.path.exists(self.target_script):
            logging.error(f"Error: Target script not found: {self.target_script}")
            return False

        print(f"Phase 3: Dynamic Runtime Tracing")
        print(f"Target: {self.target_script}\n")
        print("Executing model in sandbox and attaching strace...\n")

        try:
            # We trace 'openat' (file access, including .so loads) and 'connect' (network sockets)
            strace_cmd = [
                "strace",
                "-f",
                "-e", "trace=openat,connect",
                "-o", self.strace_output_file,
                sys.executable, self.target_script
            ]
            
            # Run the command. We don't want the script's stdout cluttering our report, 
            # so we pipe stderr/stdout to DEVNULL (or you could log it separately).
            subprocess.run(strace_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Error during script execution: Script may have crashed or strace failed. {e}")
            return False
        except FileNotFoundError:
            logging.error("strace is not installed. Please run: sudo apt install strace")
            return False

    def parse_strace_output(self):
        """Reads the strace log file and extracts network/library heuristics."""
        if not os.path.exists(self.strace_output_file):
            return

        with open(self.strace_output_file, 'r') as f:
            for line in f:
                # 1. Detect Native Library Loads (.so)
                if "openat" in line and ".so" in line:
                    try:
                        # Extract the filepath from the strace line, e.g., openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", ...
                        path_start = line.find('"') + 1
                        path_end = line.find('"', path_start)
                        if path_start > 0 and path_end > path_start:
                            filepath = line[path_start:path_end]
                            # Shared predicate: identical rule to the static scanner,
                            # so versioned sonames (libcublas.so.12) are treated the same
                            # in both phases. This is what makes the gap analysis honest.
                            if is_native_lib(filepath):
                                self.native_libraries_loaded.add(filepath)
                    except Exception:
                        pass
                
                # 2. Detect Network Connections
                #
                # A network shadow dependency is a *remote host* the pipeline
                # contacts, so the endpoint identity is the destination IP
                # (deduped by host), NOT ip:port. Keying on ip:port double-counts
                # every host: strace records both the real data connection
                # (sin_port=htons(443)) and a separate resolver / happy-eyeballs
                # route probe to the same host at port 0. A connect() to port 0
                # never carries data, so it is dropped, not counted. Both IPv4
                # (inet_addr) and IPv6 (inet_pton(AF_INET6, ...)) are parsed --
                # earlier only IPv4 was captured, silently dropping real IPv6
                # hosts even though the AF_INET6 lines were reaching this branch.
                elif "connect" in line and ("AF_INET" in line or "AF_INET6" in line):
                    try:
                        ip = None
                        port = None

                        # IPv4: sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")
                        if "sin_addr=inet_addr" in line:
                            ip_start = line.find('sin_addr=inet_addr("') + 20
                            ip_end = line.find('"', ip_start)
                            if ip_start > 19 and ip_end > ip_start:
                                ip = line[ip_start:ip_end]
                            p_start = line.find('sin_port=htons(') + 15
                            if p_start > 14:
                                p_end = line.find(')', p_start)
                                port = line[p_start:p_end]

                        # IPv6: sin6_port=htons(443), inet_pton(AF_INET6, "2600:...", &sin6_addr)
                        elif "inet_pton(AF_INET6" in line:
                            marker = 'inet_pton(AF_INET6, "'
                            ip_start = line.find(marker) + len(marker)
                            ip_end = line.find('"', ip_start)
                            if ip_start > len(marker) - 1 and ip_end > ip_start:
                                ip = line[ip_start:ip_end]
                            p_start = line.find('sin6_port=htons(') + 16
                            if p_start > 15:
                                p_end = line.find(')', p_start)
                                port = line[p_start:p_end]

                        # Keep only real REMOTE hosts: a globally-routable IP
                        # contacted on a non-zero data port. is_global rejects
                        # loopback, wildcard, RFC1918 private ranges, link-local,
                        # AND the 100.64.0.0/10 CGNAT block used by local VPN
                        # daemons (Tailscale's 100.100.100.100 MagicDNS resolver,
                        # WARP, etc.). Those are machine-specific local
                        # infrastructure, not AI supply-chain endpoints, so
                        # counting them would make the result non-reproducible on
                        # a reviewer's machine. A network shadow dependency is a
                        # remote host the pipeline reaches out to.
                        if ip and port not in (None, "", "0"):
                            try:
                                if ipaddress.ip_address(ip).is_global:
                                    self.network_connections.add(ip)
                            except ValueError:
                                pass  # not a parseable IP literal; skip
                    except Exception:
                        pass

    def get_results(self) -> Dict[str, Any]:
        """Returns and prints the parsed findings, classified by origin.

        Each loaded native library is partitioned by the paper's origin function
        Pi -> {eco, stdlib, sys, ext}:
            eco    : under site-packages  -> attributable to a declared pip package
            stdlib : CPython's own stdlib extension (lib-dynload) / libpython.so
                     -> interpreter TCB, disclosed but NOT in the headline gap
            sys    : under /usr/lib, /lib -> OS/system library (no declaring package)
            ext    : anywhere else        -> external artifact
        The headline gap treats sys + ext (plus network endpoints) as shadow;
        stdlib is reported separately so the interpreter's own internals cannot
        inflate the metric.
        """

        # Partition the loaded libraries by origin.
        eco_libs, stdlib_libs, sys_libs, ext_libs = [], [], [], []
        for lib in sorted(self.native_libraries_loaded):
            origin = classify_origin(lib)
            if origin == "eco":
                eco_libs.append(lib)
            elif origin == "stdlib":
                stdlib_libs.append(lib)
            elif origin == "sys":
                sys_libs.append(lib)
            else:
                ext_libs.append(lib)

        print("Result")

        # List Network Connections
        if self.network_connections:
            print(f"  Remote network connections: {len(self.network_connections)} detected")
            for conn in list(self.network_connections)[:25]:
                # conn is now a bare destination IP (v4 or v6); use it directly.
                try:
                    hostname, _, _ = socket.gethostbyaddr(conn)
                    print(f"    - -> [{hostname}] {conn}")
                except socket.herror:
                    print(f"    - -> [UNKNOWN HOST] {conn}")

            if len(self.network_connections) > 25:
                print("    - ... (and more)")
        else:
            print("  Remote network connections: none detected")

        # List Native Binary Loads, broken down by origin.
        total_libs = len(self.native_libraries_loaded)
        if total_libs:
            print(f"  Native libraries (.so) loaded dynamically: {total_libs}")
            print(f"    - {len(eco_libs)} from Python packages (site-packages)   [visible / declared]")
            print(f"    - {len(stdlib_libs)} from the CPython standard library      [interpreter TCB, excluded from gap]")
            print(f"    - {len(sys_libs)} from system paths (/usr/lib, /lib)      [shadow: SD-4]")
            print(f"    - {len(ext_libs)} from external/unclassified locations     [shadow: SD-2a/ext]")
            for lib in (sys_libs + ext_libs)[:3]:
                short_path = "/".join(lib.split("/")[-3:])
                print(f"    - shadow e.g. .../{short_path}")
            if len(sys_libs) + len(ext_libs) > 3:
                print("    - ... (and more)")
        else:
            print("  Native libraries (.so) loaded: none detected")

        print("")

        return {
            "network_connections": list(self.network_connections),
            "native_libraries_loaded": list(self.native_libraries_loaded),
            # Origin-partitioned sets for the gap analysis (paper Pi function).
            "eco_libs": eco_libs,       # declared / visible
            "stdlib_libs": stdlib_libs, # interpreter standard library (excluded from headline gap)
            "sys_libs": sys_libs,       # shadow (system)
            "ext_libs": ext_libs,       # shadow (external)
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 src/runtime_tracer.py <path_to_model_script.py>")
        sys.exit(1)
        
    script_to_trace = sys.argv[1]
    tracer = RuntimeTracer(script_to_trace)
    
    # Run the script under strace and parse the logs
    if tracer.run_strace():
        tracer.parse_strace_output()
        tracer.get_results()
