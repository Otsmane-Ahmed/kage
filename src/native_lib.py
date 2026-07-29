r"""
native_lib.py — Single source of truth for native-library detection and origin
classification, shared by the static phase (dependency_analyzer.py) and the
dynamic phase (runtime_tracer.py).

Why this module exists
----------------------
The original prototype used two DIFFERENT predicates to decide "is this a native
library?":

    static phase  : name.endswith('.so')                    # missed libcublas.so.12
    dynamic phase : name.endswith('.so') or '.so.' in name  # counted it

Because the two phases counted the SAME files with different rules, the reported
"shadow dependency gap" partly measured that inconsistency rather than a real
blind spot. This module gives both phases ONE predicate and ONE identity, so the
gap analysis in main.py is an honest set-difference:

    D_shadow = D_runtime \ (D_declared u D_transitive)      # paper Eq. (1)

Origin classification below implements the paper's partition function
Pi : L -> {eco, stdlib, sys, ext}  (Section 4, "Phase 3"):

    eco    -> library lives under site-packages/dist-packages => attributable to a
              declared pip package (part of D_declared u D_transitive, i.e.
              "visible / the receipt").
    stdlib -> library is part of the CPython interpreter itself: a standard-library
              C extension under .../pythonX.Y/lib-dynload/, or libpythonX.Y.so.
              These ship WITH the interpreter (batteries-included); they are not a
              third-party supply-chain artifact. They are DISCLOSED as part of the
              runtime surface but are EXCLUDED from the headline shadow gap so the
              metric cannot be inflated by the interpreter's own internals.
    sys    -> a genuine OS/system shared library under /usr/lib, /lib, ... with no
              declaring pip package (e.g. libc, libssl, libgomp) => shadow (SD-4).
              These are a real attack surface (see Case Study 3: a bundled OpenSSL
              CVE), which is why they stay IN the headline shadow set.
    ext    -> anywhere else => unclassified external artifact => shadow.

Rationale for the stdlib tier (peer-review defensibility)
---------------------------------------------------------
A skeptical reviewer will object if the interpreter's own standard-library
modules (_asyncio.so, _ctypes.so, ...) are counted as "shadow supply-chain
dependencies", because they enter with the interpreter, are not pip-installed,
and are not attacker-controllable in any normal sense. Reporting them in their
own tier — visible in the surface, absent from the headline gap — pre-empts that
objection while remaining fully transparent (nothing is hidden).
"""

import re
import os

# One predicate for BOTH phases. Matches a native shared object whether or not it
# carries a version suffix. Each version segment must BEGIN with a digit, which is
# true of every real soname (.so.6, .so.1.1.1k) and avoids matching things like
# "README.so.md":
#   libc10.so             -> match
#   libgomp-a34b3233.so.1 -> match
#   libcublas.so.12       -> match
#   libssl.so.1.1.1k      -> match   (segments start with a digit)
#   README.so.md          -> NO match ("md" segment does not start with a digit)
#   foo.socket            -> NO match (".so" must be a real extension boundary)
_NATIVE_SO = re.compile(r"\.so(?:\.[0-9][0-9A-Za-z]*)*$")

# CPython standard-library C extensions live in a "lib-dynload" directory next to
# the interpreter, e.g. /usr/lib/python3.13/lib-dynload/_asyncio.cpython-313-...so
_STDLIB_DYNLOAD = re.compile(r"/python3(?:\.[0-9]+)?/lib-dynload/")
# The interpreter shared library itself, e.g. libpython3.13.so.1.0
_LIBPYTHON = re.compile(r"^libpython3(?:\.[0-9]+)?\.so")


def is_native_lib(path_or_name: str) -> bool:
    """True iff the given filename/path is a native shared object (.so / .so.X...)."""
    if not path_or_name:
        return False
    return bool(_NATIVE_SO.search(path_or_name.strip()))


def classify_origin(path: str) -> str:
    """
    Implements the paper's origin partition Pi(l) -> {'eco','stdlib','sys','ext'}.

    'eco'    : under a site-packages/dist-packages tree  (declared pip package -> visible)
    'stdlib' : CPython's own stdlib extension (lib-dynload) or libpythonX.Y.so
               (interpreter TCB -> disclosed, NOT in the headline shadow gap)
    'sys'    : under /usr/lib, /lib, ... (OS/system library -> shadow, SD-4)
    'ext'    : anything else            (external artifact  -> shadow)

    Order matters: 'eco' wins first (a library bundled in a package is attributable
    to that package even if it also happens to sit under a system path in another
    copy); then 'stdlib' is checked BEFORE 'sys' because lib-dynload lives under
    /usr/lib.
    """
    if not path:
        return "ext"
    p = path.replace("\\", "/")

    # Ecosystem: the library is bundled inside an installed Python package.
    if "site-packages" in p or "dist-packages" in p:
        return "eco"

    # Interpreter standard library (checked before 'sys' — lib-dynload is under /usr/lib).
    if _STDLIB_DYNLOAD.search(p) or _LIBPYTHON.match(os.path.basename(p)):
        return "stdlib"

    # System: standard OS shared-library locations.
    norm = os.path.normpath(p)
    system_prefixes = (
        "/usr/lib", "/usr/lib64", "/usr/local/lib",
        "/lib", "/lib64",
    )
    if norm.startswith(system_prefixes):
        return "sys"

    return "ext"


def is_shadow(path: str) -> bool:
    """
    True iff a runtime native library counts toward the HEADLINE shadow gap.

    A library is headline-shadow iff it is neither attributable to a declared pip
    package ('eco') nor part of the interpreter's own standard library ('stdlib').
    That leaves genuine third-party system libraries ('sys') and external
    artifacts ('ext'). (Network endpoints are handled separately in the gap
    analysis; they are always shadow.)
    """
    return classify_origin(path) in ("sys", "ext")


def canonical_lib_id(path: str) -> str:
    """
    Canonical identity for set operations and de-duplication.

    strace resolves the same library through several symlinked paths
    (e.g. /usr/lib/x86_64-linux-gnu/libssl.so.3 vs a versioned alias). For the
    set-difference we key on the *basename*, which is what actually names the
    binary, so the same physical library is not double-counted.
    """
    if not path:
        return ""
    return os.path.basename(path.replace("\\", "/").strip())
