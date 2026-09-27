# `attack_surface_approximation` 🤺

---

- [Description](#description)
  - [Limitations](#limitations)
- [How It Works](#how-it-works)
- [Setup](#setup)
- [Usage](#usage)
  - [As a CLI Tool](#as-a-cli-tool)
    - [Arguments Dictionary Generation](#arguments-dictionary-generation)
    - [Input Streams Detection](#input-streams-detection)
    - [Arguments Fuzzing](#arguments-fuzzing)
    - [Help](#help)
  - [As a Python Module](#as-a-python-module)
    - [Input Streams Detection](#input-streams-detection-1)
    - [Arguments Fuzzing](#arguments-fuzzing-1)

---

## Description

`attack_surface_approximation` is the CRS module that deals with the approximation of the attack surface in a vulnerable program.

Some input mechanisms are omitted: elements of the user interface, signals, devices and interrupts. At the moment, the supported mechanisms are the following:
- Files;
- Arguments;
- Standard input;
- Networking; and
- Environment variables.

In addition, a custom fuzzer is implemented to discover arguments that trigger different code coverage. It takes arguments from a dictionary which can be handcrafted or generated with an exposed command, with an implemented heuristic.

Examples of arguments dictionaries can be found in `examples/dictionaries`:
- `man.txt`, generated with the `man_parsing` heuristic and having 6605 entries; and
- `common.txt`, generated with the `generation` heuristic and having 62 entries.

### Limitations

- ELF format
- x86 architecture (32-bit)
- Non-static binaries
- Symbols present (namely, no stripping is involved); binaries compiled without debug symbols (`-g`) may cause Ghidra to fail resolving function calls, leading to incomplete detection results
- No obfuscation technique involved
- **Binary compatibility for fuzzing**: the argument fuzzer runs inside a Docker container based on Ubuntu 18.04 (GLIBC 2.27). Binaries compiled on modern systems that require a newer GLIBC version will fail to execute inside the container. To work around this, compile the target binary inside the QBDI Docker container itself before fuzzing.
- **Incomplete argument detection**: flags that trigger identical QBDI basic block paths (e.g., multiple simple flags that all resolve to a `break` in a switch statement) will share the same hash. Only the first occurrence is reported; subsequent flags with the same hash are suppressed by the deduplication mechanism.
- **False positive filtering relies on `getopt` stderr reporting**: the module filters out invalid options by checking whether the binary writes to stderr when run with that argument — standard `getopt` behavior. Programs that use custom option parsers and suppress error output may still produce false positives.
- **External library dependencies**: the QBDI Docker container (Ubuntu 18.04 minimal) does not include non-standard system libraries (e.g., `libmysqlclient`, `libpam`). Binaries that depend on such libraries at runtime cannot be instrumented by the fuzzer, and cannot be compiled inside the container.
- **Dictionary-dependent fuzzing**: the fuzzer can only discover arguments that appear in the provided dictionary. Arguments not covered by the dictionary will never be detected, regardless of their effect on the program.
- **No combined argument testing**: each argument is tested individually. Programs that change execution flow only when specific argument combinations are provided (e.g., `-f file -v`) will not have those combinations detected.
- **Runtime environment requirements**: binaries that require a specific environment to run correctly (elevated privileges, particular files or sockets present, specific environment variables set) may produce incorrect or incomplete fuzzing results.
- **Indirect input not detected**: programs that receive input through child processes, pipes, or `popen` calls are not covered by the static detection heuristics.
- **Static STDIN/FILES detection is over-approximate**: the static detector checks whether the binary's imported function table (PLT) contains known I/O functions (e.g. `fread`, `fgets`, `read`). Because these functions accept an arbitrary file descriptor, a binary that reads exclusively from a file or device (e.g. `/dev/urandom`) using `fread` will be incorrectly flagged as reading from standard input. Resolving this accurately would require data-flow analysis to determine which file descriptor is passed at each call site — not feasible at PLT level. The dynamic QBDI pass corrects any such false positives in the final `analyze` output.

## How It Works

The module works by automating Ghidra for static binary analysis. It extracts information and applies heuristics to determine if a given input stream is present.

Examples of such heuristics are:
- For standard input, calls to `getc()` and `gets()`
- For networking, calls to `recv()` and `recvfrom()`
- For arguments, occurrences of `argc` and `argv` in the `main()`'s decompilation.

The argument fuzzer uses Docker and QBDI to detect basic block coverage.

## Setup

1. Ensure you have Docker installed.
2. Install the required Python 3 packages via `poetry install`.
3. Initialize the Ghidra Docker submodule and build its image:
   ```
   cd commons && git submodule update --init commons/ghidra/docker && cd ..
   cd commons/commons/ghidra/docker
   docker build -t ghidra .
   ```
4. Build the QBDI Docker image:
   ```
   cd commons/commons/qbdi/docker
   docker build -t opencrs/qbdi .
   ```
5. Ensure the Docker API is accessible by:
   - Running the module as `root`; or
   - Adding your user to the `docker` group: `sudo usermod -aG docker $USER` (log out and back in for it to take effect).

## Usage

### As a CLI Tool

#### Arguments Dictionary Generation

```
➜ poetry run attack_surface_approximation generate --heuristic man_parsing --output args.txt --top 10
Successfully generated dictionary with 10 arguments
➜ cat args.txt
--and
--get
--get-feedbacks
--no-progress-meter
--print-name
-input
-lmydep2
-miniswhite
-nM
-prune
```

#### Input Streams Detection

```
➜ ./crackme
Enter the password: pass
Wrong password!
➜ poetry run attack_surface_approximation detect --elf crackme
Several input mechanisms were detected for the given program:

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Stream                ┃ Present ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ files                 │   No    │
│ arguments             │   No    │
│ stdin                 │   Yes   │
│ networking            │   No    │
│ environment_variables │   No    │
└───────────────────────┴─────────┘
```

#### Arguments Fuzzing

The target binary must be a 32-bit ELF dynamically linked against GLIBC 2.27 or earlier. If your binary was compiled on a modern system, compile it inside the QBDI container first:

```
➜ docker run --rm --user root \
    -v $(pwd)/examples:/examples \
    opencrs/qbdi \
    bash -c "gcc -m32 /examples/target.c -o /examples/target"
```

Then run the fuzzer:

```
➜ poetry run attack_surface_approximation fuzz --elf examples/target --dictionary args.txt
Several arguments were detected for the given program:

┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Argument               ┃      Role      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ -d                     │      FLAG      │
│ -f string              │ STRING_ENABLER │
│ -r                     │      FLAG      │
│ -s                     │      FLAG      │
│ -v                     │      FLAG      │
│ -f /tmp/canary.opencrs │  FILE_ENABLER  │
└────────────────────────┴────────────────┘
```

#### Help

```
➜ poetry run attack_surface_approximation
Usage: attack_surface_approximation [OPTIONS] COMMAND [ARGS]...

  Discovers the attack surface of vulnerable programs.

Options:
  --help  Show this message and exit.

Commands:
  analyze   Analyze with all methods.
  detect    Statically detect what input streams are used by an executable.
  fuzz      Fuzz the arguments of an executable.
  generate  Generate dictionaries with arguments, based on heuristics.
```

### As a Python Module

#### Input Streams Detection

```python
from attack_surface_approximation.static_input_streams_detection import \
    InputStreamsDetector

detector = InputStreamsDetector(elf_filename)
streams_list = detector.detect_all()
```

#### Arguments Fuzzing

```python
from attack_surface_approximation.arguments_fuzzing import ArgumentsFuzzer

with ArgumentsFuzzer(elf_filename, fuzzed_arguments) as fuzzer:
    detected_arguments = fuzzer.get_all_valid_arguments()
```
