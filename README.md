# `attack_surface_discovery` 🤺

## Description 🖼️

**`attack_surface_discovery`** is the CRS module that deals with the **discovery of the attack surface in a vulnerable program**.

Some input mechanisms are omitted: elements of the user interface, signals, devices and interrupts. At the moment, the **supported mechanisms** are the following:
- Files;
- Arguments;
- Standard input;
- Networking; and
- Environment variables.

To limit the research scope, some **constraints** were imposed for the analyzed programs:
- ELF format;
- x86 architecture;
- Symbols present (namely, no stripping is involved); and
- No obfuscation technique involved.

## Setup 🔧

Only install the required packages via `pip3 install -r requirements.txt`.

## Usage 🧰

The module can be used both **as a CLI tool**, by using the script `cli.py`.

```
./cli.py tests/multiple_inputs/multiple_inputs.elf
[+] Several input mechanisms were detected for the given program:
    - Files
    - Arguments
    - Standard input
    - Networking
    - Environment variables
```

In the same time, it can be imported as a **Python 3 module**.