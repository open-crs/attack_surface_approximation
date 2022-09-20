"""Python 2 script for dumping all the called functions

This script uses Ghidra for traversing the function of an ELF, getting all the
called functions and printing them on screen.
"""

# pylint: skip-file
# flake8: noqa

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

REPORT_DELIMITOR = 16 * "*"


def extract_calls():
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)

    called_functions = set()
    for function in functions:
        current_called_functions = function.getCalledFunctions(
            TaskMonitor.DUMMY
        )
        for called_function in current_called_functions:
            called_functions.add(called_function)

    for called_function in called_functions:
        print(called_function)


def decompile_main():
    program = getCurrentProgram()
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    function = getGlobalFunctions("main")[0]

    results = decompiler.decompileFunction(function, 0, ConsoleTaskMonitor())
    code = results.getDecompiledFunction().getC()

    print(code)


def print_delimitpr():
    print(REPORT_DELIMITOR)


def main():
    decompile_main()
    print_delimitpr()
    extract_calls()


if __name__ == "__main__":
    main()
