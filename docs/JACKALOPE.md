# Jackalope Integration

ALF integrates with Google Project Zero's [Jackalope](https://github.com/googleprojectzero/Jackalope) fuzzer for high-performance coverage-guided fuzzing with TinyInst binary instrumentation.

## Overview

The integration uses a "Sandwich Fuzzing" pattern:

1. **Cold Start**: LLM analyzes the target binary and generates initial seeds
2. **Grind**: Jackalope runs at native speed with TinyInst coverage feedback
3. **Triage Loop**: LLM analyzes crashes via LLDB and injects refined seeds back

This combines the speed of native fuzzing with the intelligence of LLM-guided mutation and crash analysis.

## Prerequisites

### Build Jackalope

Clone and build Jackalope with TinyInst:

```bash
git clone --recurse-submodules https://github.com/googleprojectzero/Jackalope.git
cd Jackalope

# macOS
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

The fuzzer binary will be at `build/fuzzer` (or `build/Release/fuzzer` on some systems).

### Create a Harness

For macOS framework fuzzing, create a harness that exposes a target function:

```c
// harness.m
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>

int fuzz(const char *filename) {
    @autoreleasepool {
        NSURL *url = [NSURL fileURLWithPath:@(filename)];
        CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)url, NULL);
        if (source) {
            CGImageRef image = CGImageSourceCreateImageAtIndex(source, 0, NULL);
            if (image) CFRelease(image);
            CFRelease(source);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    return fuzz(argv[1]);
}
```

Compile:
```bash
clang -framework Foundation -framework ImageIO -framework CoreGraphics \
    -o harness harness.m
```

## Usage

### Basic Usage

```bash
uv run alf fuzz jackalope ./target \
    --fuzzer /path/to/jackalope/fuzzer \
    --corpus ./seeds
```

### macOS Framework Fuzzing

```bash
uv run alf fuzz jackalope ./harness \
    --fuzzer /path/to/fuzzer \
    --corpus ./in \
    --output ./out \
    --instrument-module ImageIO \
    --target-module harness \
    --target-method _fuzz \
    --persist \
    --delivery shmem \
    --threads 4 \
    --max-time 3600
```

### Without LLM Cold Start

If you already have a corpus, skip LLM seed generation:

```bash
uv run alf fuzz jackalope ./target \
    --fuzzer ./fuzzer \
    --corpus ./existing_seeds \
    --no-cold-start
```

## Command Options

### Required

| Option | Description |
|--------|-------------|
| `TARGET` | Path to the target binary/harness |
| `--fuzzer` | Path to Jackalope fuzzer binary |
| `--corpus` | Input corpus directory |

### TinyInst Options

| Option | Description |
|--------|-------------|
| `--instrument-module` | Module to instrument for coverage (e.g., `ImageIO`) |
| `--target-module` | Module containing the target function |
| `--target-method` | Target function name (e.g., `_fuzz`) |
| `--nargs` | Number of arguments to target method |

### Execution Options

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | 1000 | Sample timeout in milliseconds |
| `--init-timeout` | 5000 | Initialization timeout in milliseconds |
| `--iterations` | 5000 | Iterations before process restart |
| `--threads` | 1 | Parallel fuzzing threads |
| `--persist/--no-persist` | `--persist` | Reuse process across iterations |
| `--max-time` | 3600 | Maximum fuzzing time in seconds |

### Delivery Options

| Option | Default | Description |
|--------|---------|-------------|
| `--delivery` | `file` | Sample delivery method (`file` or `shmem`) |
| `--delivery-dir` | None | Delivery directory (e.g., `/Volumes/RAMDisk`) |
| `--file-extension` | None | File extension for samples (e.g., `png`, `mov`) |
| `--output` | `corpus/../out` | Output directory for crashes |

### LLM Options

| Option | Default | Description |
|--------|---------|-------------|
| `--cold-start/--no-cold-start` | `--cold-start` | Run LLM seed synthesis at start |
| `--provider` | auto-detect | LLM provider for analysis |
| `--model` | from config | LLM model for analysis |
| `--triage-interval` | 60 | Seconds between crash triage cycles |

## Example Workflows

### Fuzzing ImageIO

```bash
# Prepare corpus with sample images
mkdir -p corpus
cp /path/to/sample.png corpus/

# Run fuzzer
uv run alf fuzz jackalope ./imageio_harness \
    --fuzzer /path/to/jackalope/fuzzer \
    --corpus ./corpus \
    --output ./crashes \
    --instrument-module ImageIO \
    --target-module imageio_harness \
    --target-method _fuzz \
    --persist \
    --delivery shmem \
    --file-extension png \
    --threads 4 \
    --max-time 7200
```

### Fuzzing AudioCodecs

```bash
uv run alf fuzz jackalope ./audiodecode \
    --fuzzer /path/to/fuzzer \
    --corpus ./audio_samples \
    --instrument-module AudioCodecs \
    --target-module audiodecode \
    --target-method _fuzz \
    --delivery shmem \
    --delivery-dir /Volumes/RAMDisk \
    --file-extension mov \
    --max-sample-size 2000000
```

### High-Performance Setup

For maximum performance:

```bash
# Create RAM disk for sample delivery
diskutil erasevolume HFS+ "RAMDisk" `hdiutil attach -nomount ram://2097152`

# Run with optimized settings
uv run alf fuzz jackalope ./harness \
    --fuzzer ./fuzzer \
    --corpus ./in \
    --delivery shmem \
    --delivery-dir /Volumes/RAMDisk \
    --persist \
    --threads 8 \
    --iterations 10000 \
    --no-cold-start
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   JackalopeHybridFuzzer                         │
├─────────────────────────────────────────────────────────────────┤
│  Phase 1: Cold Start                                            │
│  ├─ InputGenerator.synthesize_from_binary()                     │
│  ├─ Writes seeds to corpus_dir/                                 │
│  └─ Falls back to heuristic_mutations() if LLM fails            │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2: Grind                                                 │
│  ├─ JackalopeOrchestrator.launch()                              │
│  │   └─ Spawns: fuzzer -in corpus -out out ... -- target @@     │
│  ├─ Parses stdout for coverage/corpus stats                     │
│  └─ JackalopeCrashMonitor watches output_dir for crashes        │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3: Triage Loop (every triage_interval seconds)           │
│  ├─ Detects new crash_*/hang_* files in output_dir              │
│  ├─ FuzzSession.launch() with crash input                       │
│  ├─ Computes stack hash for deduplication                       │
│  ├─ heuristic_mutations() generates refined seeds               │
│  └─ JackalopeOrchestrator.inject_seed() → corpus_dir            │
└─────────────────────────────────────────────────────────────────┘
```

## Jackalope Command Reference

The `alf fuzz jackalope` command builds a Jackalope command line like:

```bash
./fuzzer \
    -in corpus/ \
    -out out/ \
    -t 1000 \
    -t1 5000 \
    -nthreads 4 \
    -iterations 5000 \
    -persist \
    -loop \
    -mute_child \
    -cmp_coverage \
    -delivery shmem \
    -delivery_dir /Volumes/RAMDisk \
    -file_extension png \
    -instrument_module ImageIO \
    -target_module harness \
    -target_method _fuzz \
    -nargs 1 \
    -- ./harness @@
```

## Troubleshooting

### Fuzzer exits immediately

- Check that the target binary exists and is executable
- Verify Jackalope fuzzer path is correct
- Try running Jackalope directly to see error messages

### No coverage

- Ensure `--instrument-module` matches the module you want to instrument
- For persistent mode, verify `--target-method` matches your function name
- Check that TinyInst supports your target architecture

### Crashes not detected

- Verify `--output` directory is writable
- Check Jackalope is writing crashes (look for `crash_*` files in output dir)
- Increase `--triage-interval` if crashes are being missed

### LLM cold start fails

- Check LLM provider API key is set
- Use `--no-cold-start` to skip LLM seed generation
- Provide initial seeds manually in corpus directory
