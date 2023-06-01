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
- `man.txt`, generated with the `man` heurstic and having 6605 entries; and
- `common.txt`, generated with the `common` heuristic and having 62 entries.

### Limitations

- ELF format
- x86 architecture
- Non-static binaries
- Symbols present (namely, no stripping is involved)
- No obfuscation technique involved

## How It Works

The module works by automating Ghidra for static binary analysis. It extracts information and apply heuristics to determine if a given input stream is present.

Examples of such heuristics are:
- For standard input, calls to `getc()` and `gets()`
- For networking, calls to `recv()` and `recvfrom()`
- For arguments, occurrences of `argc` and `argv` in the `main()`'s decompilation.

The argument fuzzer uses Docker and QBDI to detect basic block coverage.

## Setup

1. Download Ghidra in `/opencrs/ghidra` or in a location at your choice. In the latter case, place the path into `Configuration.GhidraDecompilation.FOLDER` from `configuration.py`.
2. Ensure you have Docker installed.
3. Install the required Python 3 packages via `poetry install --no-dev`.
4. Build the Docker image: `docker build --tag qbdi_args_fuzzing -f docker/Dockerfile.qbdi_docker docker`.
5. Ensure the Docker API is accessible by:
   - Running the module as `root`; or
   - Changing the Docker socket permissions (unsecure approach) via `chmod 777 /var/run/docker.sock`.

## Usage

### As a CLI Tool

#### Arguments Dictionary Generation

```
➜ poetry run attack_surface_approximation generate --heuristic man --output args.txt --top 10
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

```
➜ poetry run attack_surface_approximation fuzz --elf /bin/uname --dictionary args.txt
Several arguments were detected for the given program:

┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Argument  ┃      Role      ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ -         │      FLAG      │
│ -a        │      FLAG      │
│ -a string │ STRING_ENABLER │
│ -i        │      FLAG      │
│ -i string │ STRING_ENABLER │
│ -m        │      FLAG      │
│ -m string │ STRING_ENABLER │
│ -n        │      FLAG      │
│ -n string │ STRING_ENABLER │
│ -o        │      FLAG      │
│ -o string │ STRING_ENABLER │
│ -p        │      FLAG      │
│ -p string │ STRING_ENABLER │
│ -r        │      FLAG      │
│ -r string │ STRING_ENABLER │
│ -s        │      FLAG      │
│ -s string │ STRING_ENABLER │
│ -v        │      FLAG      │
│ -v string │ STRING_ENABLER │
└───────────┴────────────────┘
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
streams = detector.detect_all()
```

#### Arguments Fuzzing

```python
from attack_surface_approximation.arguments_fuzzing import ArgumentsFuzzer

fuzzer = ArgumentsFuzzer(elf_filename, fuzzed_arguments)
detected_arguments = fuzzer.get_all_valid_arguments()
```