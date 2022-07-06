# `attack_surface_approximation` 🤺

## Description 🖼️

**`attack_surface_approximation`** is the CRS module that deals with the **approximation of the attack surface in a vulnerable program**.

Some input mechanisms are omitted: elements of the user interface, signals, devices and interrupts. At the moment, the **supported mechanisms** are the following:
- Files;
- Arguments;
- Standard input;
- Networking; and
- Environment variables.

## How It Works 🪄

The module works by automating Ghidra for static binary analysis. It extracts information and apply heuristics to determine if a given input stream is present.

Examples of such heuristics are:
- For standard input, calls to `getc()` and `gets()`;
- For networking, calls to `recv()` and `recvfrom()`; and
- For arguments, occurrences of `argc` and `argv` in the `main()`'s decompilation; and

## Limitations 🚧

To limit the research scope, some **constraints** were imposed for the analyzed programs:
- ELF format;
- x86 architecture;
- Symbols present (namely, no stripping is involved); and
- No obfuscation technique involved.

## Setup 🔧

Only install Ghidra in `/opt/ghidra` and the required packages via `poetry install --no-dev`.

## Usage 🧰

The module can be imported as a **Python 3 module** or used **as a CLI tool**.