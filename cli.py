#!/usr/bin/env python3

import os
import sys

from attack_surface_approximation import AttackSurfaceApproximation


def main() -> None:
    # Check the arguments
    if (len(sys.argv) != 2) or (not os.path.isfile(sys.argv[1])):
        print("[!] Invalid number or value of arguments")
        exit()

    # Discover
    filename = sys.argv[1]
    approximation = AttackSurfaceApproximation(filename)
    input_types = approximation.detect_all()

    # Log
    files = input_types.files
    arguments = input_types.arguments
    stdin = input_types.stdin
    networking = input_types.networking
    environment_variables = input_types.environment_variables
    if not (files or arguments or stdin or networking
            or environment_variables):
        print("[!] No input mechanism was detected for the given program.")
    else:
        print(
            "[+] Several input mechanisms were detected for the given program:"
        )
        if files:
            print("\t- Files")
        if arguments:
            print("\t- Arguments")
        if stdin:
            print("\t- Standard input")
        if networking:
            print("\t- Networking")
        if environment_variables:
            print("\t- Environment variables")

if __name__ == "__main__":
    main()