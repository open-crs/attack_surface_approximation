# `attack_surface_approximation` 🤺

---

- [Description](#description)
  - [Limitations](#limitations)
- [How It Works](#how-it-works)
- [Setup](#setup)

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

### Limitations

- ELF format
- x86 architecture
- Symbols present (namely, no stripping is involved)
- No obfuscation technique involved

## How It Works

The module works by automating Ghidra for static binary analysis. It extracts information and apply heuristics to determine if a given input stream is present.

Examples of such heuristics are:
- For standard input, calls to `getc()` and `gets()`
- For networking, calls to `recv()` and `recvfrom()`
- For arguments, occurrences of `argc` and `argv` in the `main()`'s decompilation.

The argument fuzzer uses Docker and  QBDI to detect basic block coverage.

## Setup

1. Install Ghidra in `/opt/ghidra`.
2. Install the required Python 3 packages via `poetry install --no-dev`.