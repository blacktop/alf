# libplist harness

Real‑world demo harness targeting the vendored `libplist` binary/XML parser.

## What it fuzzes
`fuzz_libplist.c` calls `plist_from_bin()` on arbitrary inputs to exercise container parsing, length fields, and nested object handling. The library is built with ASan/UBSan via `make libplist`.

## Build
```bash
# compile libplist + harness with sanitizers
bash harnesses/libplist/build.sh
# (fish wrapper)
fish harnesses/libplist/build.fish
```

## Smoke fuzz
```bash
# short sanity run, artifacts in crashes/libplist and logs/
fish harnesses/libplist/smoke.fish
```

## Reproduce / triage
```bash
harnesses/libplist/out/fuzz_libplist -runs=1 crashes/libplist/crash-XXXX
bash scripts/triage_once.sh harnesses/libplist/out/fuzz_libplist crashes/libplist/crash-XXXX demo
python3 scripts/lldb_mcp_triage.py --binary harnesses/libplist/out/fuzz_libplist --crash crashes/libplist/crash-XXXX --tag demo
```

