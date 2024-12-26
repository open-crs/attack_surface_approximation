# `attack_surface_approximation` 🤺

---

- [Description](#description)
  - [Limitations](#limitations)
- [How It Works](#how-it-works)
- [Setup](#setup)
- [Usage](#usage)
  - [As a CLI Tool](#as-a-cli-tool)
    - [Generate Dictionary for Arguments](#generate-dictionary-for-arguments)
    - [Input Streams Detection](#detect-input-streams)
    - [Arguments Fuzzing](#fuzz-arguments)
    - [Get Help](#get-help)
  - [As a Python Module](#as-a-python-module)
    - [Input Streams Detection](#detect-input-streams-1)
    - [Arguments Fuzzing](#fuzz-arguments-1)

---

## Description

`attack_surface_approximation` is the CRS module that deals with the approximation of the attack surface in a vulnerable program.

Some input mechanisms are omitted: elements of the user interface, signals, devices and interrupts. At the moment, the supported mechanisms are the following:

- files
- command-line arguments
- standard input
- networking
- environment variables

In addition, a custom fuzzer is implemented to discover arguments that trigger different code coverage.
It takes arguments from a dictionary which can be handcrafted or generated with an exposed command, with an implemented heuristic.

Examples of arguments dictionaries can be found in `examples/dictionaries`:

- `man.txt`: generated with the `man_parsing` heuristic and having 6605 entries
- `generation.txt`: generated with the `generation` heuristic and having 62 entries

### Limitations

- ELF format
- x86 architecture
- dynamic binaries (static binaries are not supported)
- symbols present (namely, no stripping is involved)
- no obfuscation technique involved

## How It Works

The module works by automating [Ghidra](https://ghidra-sre.org/) for static binary analysis.
It extracts information and applies heuristics to determine if a given input stream is present.

Examples of such heuristics are:

- for standard input: calls to `getc()` and `gets()`
- for networking: calls to `recv()` and `recvfrom()`
- for command-line arguments: occurrences of `argc` and `argv` in `main()`

The argument fuzzer uses [Docker](https://www.docker.com/) for running and [QBDI](https://qbdi.quarkslab.com/) to detect basic-block coverage.

## Setup

1. Make sure you have set up the repositories and Python environment according to the [top-level instructions](https://github.com/open-crs#requirements).
   That is:

   - Docker is installed and is properly running.
     Check using:

     ```console
     docker version
     docker ps -a
     docker run --rm hello-world
     ```

     These commands should run without errors.

   - The current module repository and all other module repositories (particularly the [`dataset` repository](https://github.com/open-crs/dataset) and the [`commons` repository](https://github.com/open-crs/commons)) are cloned in the same directory.

   - You are running all commands inside a Python virtual environment.
     There should be `(.venv)` prefix to your prompt.

   - You have installed Poetry in the virtual environment.
     If you run:

     ```console
     which poetry
     ```

     you should get a path ending with `.venv/bin/poetry`.

1. Disable the Python Keyring:

   ```console
   export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
   ```

   This is an problem that may occur in certain situations, preventing Poetry from getting packages.

1. Install the required packages with Poetry (based on `pyprojects.toml`):

   ```console
   poetry install --only main
   ```

1. Create the `ghidra` and `qbdi_args_fuzzing` Docker images by using the [instructions in the `commons` repository](https://github.com/open-crs/commons?tab=readme-ov-file#setup).

1. Optionally, generate executables by using the [instructions in the `dataset` repository](https://github.com/open-crs/dataset).

## Usage

You can use the `attack_surface_approximation` module either standalone, as a CLI tool, or integrated into Python applications, as a Python module.

### As a CLI Tool

As a CLI tool, you can either use the `cli.py` module:

```console
python attack_surface_approximation/cli.py
```

or the Poetry interface:

```console
poetry run attack_surface_approximation
```

#### Generate Dictionary for Arguments

```console
$ poetry run attack_surface_approximation generate --heuristic man_parsing --output args.txt --top 100
Successfully generated dictionary with 10 arguments

$ head args.txt
--allow-unrelated-histories
--analysis-display-unstable-clusters
--auto-area-segmentation
--backup-dir
--callstack-filter
--cidfile
--class
--codename
--column
--contained
```

#### Detect Input Streams

Use an ELF i386 (32 bit) executable as target for detecting input streams.

For example, you can use one of the executables generated in the [`dataset` repository](https://github.com/open-crs/dataset):

```console
$ ../dataset/executables/toy_test_suite_1.elf
Gimme two lines of input:
aaa
bbb
```

Now, do the attack surface approximation:

```console
$ poetry run attack_surface_approximation detect --elf $(pwd)/../dataset/executables/toy_test_suite_1.elf
Several input mechanisms were detected for the given program:

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Stream               ┃ Present ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ STDIN                │   Yes   │
│ ARGUMENTS            │   Yes   │
│ FILES                │   Yes   │
│ ENVIRONMENT_VARIABLE │   Yes   │
│ NETWORKING           │   Yes   │
└──────────────────────┴─────────┘
```

The executable used uses all potential input streams.

#### Fuzz Arguments

```console
$ poetry run attack_surface_approximation fuzz --elf $(pwd)/../dataset/executables/toy_test_suite_1.elf --dictionary args.txt
Several arguments were detected for the given program:

┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Argument    ┃      Role      ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ -           │      FLAG      │
│ --re        │      FLAG      │
│ --re string │ STRING_ENABLER │
│ -mmusl      │      FLAG      │
└─────────────┴────────────────┘
```

#### Get Help

```console
$ poetry run attack_surface_approximation
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

#### Detect Input Streams

```python
from attack_surface_approximation.static_input_streams_detection import \
    InputStreamsDetector

detector = InputStreamsDetector(elf_filename)
streams_list = detector.detect_all()
```

#### Fuzz Arguments

```python
from attack_surface_approximation.arguments_fuzzing import ArgumentsFuzzer

fuzzer = ArgumentsFuzzer(elf_filename, fuzzed_arguments)
detected_arguments = fuzzer.get_all_valid_arguments()
```
