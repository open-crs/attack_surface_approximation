"""Python 2 script for dumping all the called functions

This script uses Ghidra for traversing the function of an ELF, getting all the
called functions and printing them on screen.
"""
import sys

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.database.function import FunctionDB
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor


REPORT_DELIMITOR = 16 * "*"


def extract_calls():
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)

    # Iterate through functions
    called_functions = set()
    for function in functions:
        listing = currentProgram.getListing()

        # Get the API calls for the current function
        current_called_functions = function.getCalledFunctions(
            TaskMonitor.DUMMY)
        for called_function in current_called_functions:
            # Print the name of the function
            called_functions.add(called_function)

    # Print the called function
    for called_function in called_functions:
        print(called_function)


def decompile_main():
    # Create the required objects
    program = getCurrentProgram()
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    # Find the main() function
    function = getGlobalFunctions("main")[0]

    # Decompile the function
    results = decompiler.decompileFunction(function, 0, ConsoleTaskMonitor())
    code = results.getDecompiledFunction().getC()

    # Print the C code
    print(code)

def print_delimitpr():
    print(REPORT_DELIMITOR)


def main():
    decompile_main()
    print_delimitpr()
    extract_calls()


if __name__ == "__main__":
    main()
