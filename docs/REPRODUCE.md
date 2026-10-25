# Reproduce and inspect

Run commands from this new project directory. No package download is needed.
The recorded build used Rust 1.89.0 x86_64-pc-windows-msvc and Python 3.14.

```powershell
New-Item -ItemType Directory -Path build -Force | Out-Null
rustc --edition=2021 -D warnings -C opt-level=3 -C overflow-checks=yes src/main.rs -o build/prismguard32.exe
.\build\prismguard32.exe demo
.\build\prismguard32.exe lab
python tools/verify.py
```

The harness writes its own build and evidence files, invokes the installed
compiler, and checks that the PrismLock-32 baseline stays unchanged when that
sibling folder is present. A standalone download explicitly records that the
baseline check was not performed. The script creates its build directory. No user
file is an encryption input. It does not install dependencies, delete files,
change system settings, or test attacks against other applications.

`verify.py` builds these separate executables:

| Binary | Purpose | May use real material? |
| --- | --- | --- |
| prismguard32.exe | Synthetic in-memory application using OS randomness | The demo accepts no real keys/files |
| tests.exe | Rust correctness/state/parser test groups | No |
| audit.exe | Exact F5 multiplier model, vectors, mutation campaign | No; deterministic fixture feature enabled |
| timing.exe | Timing diagnostic with negative control and retained samples | No; deterministic fixture feature enabled |
| benchmark.exe | Operation and end-to-end timing | No; synthetic keys |

Specific diagnostic commands:

```powershell
.\build\audit.exe model
.\build\audit.exe vectors
.\build\audit.exe arithmetic
.\build\audit.exe fuzz
.\build\timing.exe 10000 20261025 raw
.\build\benchmark.exe
python tools/reference.py
python tools/assembly_review.py
```

The raw timing command emits JSON summaries and ordered class/time arrays to
stdout. The verification harness stores them as CSVs under `evidence/`.
Rows preserve acquisition order. Class 0 is fixed input; class 1 is varied input.
For the negative control, class 1 deliberately takes a much longer code path.
No timings are selected or discarded from the retained raw files. Cropped
statistics use common pooled thresholds and retain the uncropped statistic too.
Exploratory statistics are not calibrated experiment-wide significance claims.

The saved assembly is target-specific. The shape checker checks selected
function bodies for conditional jumps and integer division; it is not a
constant-time dataflow verifier and does not inspect a physical device.

Devpost's Markdown layer requires doubled backslashes around inline math
(`\\(...\\)`). `docs/DEVPOST-PUBLISHED.md` records the saved, rendered body,
including reviewer links and figures. The preview was checked for rendered
inline/display equations and loaded images. Display equations use `$$...$$`.

The latest benchmark summary and the earlier summary are both retained.
Full-workflow medians differed (60.5 us and 88.5 us), illustrating ordinary
variation in OS randomness, scheduling, and environment. Do not interpret one
run's median as a stable throughput guarantee.

## Media

The PNGs and 135-second captioned MP4 are already provided. They are a
constructed walkthrough with an excerpt of actual captured demo output,
not a continuous screen recording or an independent audit.

For local regeneration, `tools/charts.ps1` uses installed .NET Charting and
`tools/media.py` uses Pillow plus installed ffmpeg. The media script downloads
nothing. If a local script policy blocks a rendering helper, leave the policy
unchanged and use the provided assets. Automatic narration was blocked on the
authoring machine; the delivered video uses captions and no voice/audio.

## Publication safety

The public-source export excludes executables, debug symbols, compiler build
outputs, the optional blocked narration helper, and the full local baseline
hash inventory. Compiler diagnostic paths are redacted to `<project>`.
It includes source, documentation, synthetic vectors, timing observations,
figures, and the local video. `MANIFEST.json` hashes every exported file.
The ZIP is checked for CRC errors, unsafe paths, and manifest consistency.
