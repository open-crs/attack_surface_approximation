import os
import subprocess
import typing

import capstone
from elftools.elf.elffile import ELFFile, SymbolTableSection
from pycparser import c_parser

from .exceptions import NotELFFileException, MainNotFoundException
from .configuration import Configuration

GHIDRA_AUTOMATION_SCRIPT = "attack_surface_discovery/ghidra_automation.py"
GHIDRA_REPORT_START_LINE = "INFO  SCRIPT"
GHIDRA_REPORT_FINISH_LINE = "INFO  ANALYZING"
TEXT_SECTION_IDENTIFIER = ".text"
MAIN_FUNCTION_NAME = "main"
REPORT_DELIMITOR = 16 * "*"
COMMENT_PREFIX = "/* WARNING"


class InputTypes:
    files: bool
    arguments: bool
    stdin: bool
    networking: bool
    environment_variables: bool

    def __init__(self):
        self.files = False
        self.arguments = False
        self.stdin = False
        self.networking = False
        self.environment_variables = False


class ParametersCheckVisitor(c_parser.c_ast.NodeVisitor):
    _parameters_names: typing.List[str]
    _are_parameters_used: bool

    def __init__(self):
        self._parameters_names = []
        self._are_parameters_used = False

    def _check_parameters_used(self, obj: object) -> None:
        # Get all the attributes of the current object
        attrs = [
            attr for attr in dir(obj)
            if not callable(getattr(obj, attr)) and not attr.startswith("__")
        ]

        # Check if the "name" member appears here
        if ("name" in attrs
                and getattr(obj, "name") in self._parameters_names):
            self._are_parameters_used = True

        # Call recursively the members of the object
        for attr in attrs:
            self._check_parameters_used(attr)

    def are_parameters_used(self) -> bool:
        return self._are_parameters_used

    def visit_ParamList(self, node: c_parser.c_ast.Node):
        # Extract the parameters of the function
        self._parameters_names = [parameter.name for parameter in node.params]

    def generic_visit(self, node: c_parser.c_ast.Node):
        # Check if the parameters are used in the current node
        self._check_parameters_used(node)

        # Call the overwritten method
        super().generic_visit(node)


class AttackSurfaceDiscovery:

    _configuration: object = Configuration.AttackSurfaceDiscovery
    _filename: str
    _elf: ELFFile
    _was_ghidra_analyzed: bool
    _calls: typing.Set[str]
    _input_types: InputTypes
    _decompiled_code: str

    def __init__(self, filename: str) -> None:
        if os.path.isfile(filename):
            self._filename = filename

            # Check if the provided file is an ELF
            given_file = open(filename, "rb")
            try:
                self._elf = ELFFile(given_file)
            except:
                raise NotELFFileException()
        else:
            raise ELFNotFoundException()

        self._was_ghidra_analyzed = False
        self._calls = set()
        self._input_types = InputTypes()
        self._decompiled_code = ""

    @staticmethod
    def _have_element_in_common(first: set, second: set) -> True:
        if not (first and second):
            return False

        common_elements = [element for element in first if element in second]

        return len(common_elements) != 0

    def _process_decompiled_code(self) -> None:
        # Replace undefs
        self._decompiled_code = self._decompiled_code.replace(
            "undefined4", "int").replace("undefined", "char")

        # Replace with longs
        self._decompiled_code = self._decompiled_code.replace("char8", "long")

        # Replace useless double line
        self._decompiled_code = self._decompiled_code.replace("\n\n", "\n")

        # Skip a line containing a comment. pycparser won't be able to
        # parse it.
        no_comments_code = []
        for line in self._decompiled_code.splitlines():
            if not COMMENT_PREFIX in line:
                no_comments_code.append(line)
        self._decompiled_code = "\n".join(no_comments_code)

    def _analyze_with_ghidra(self) -> None:
        if self._was_ghidra_analyzed:
            return

        # Ensure that the project folder is created
        if not os.path.isdir(self._configuration.GHIDRA_PROJECT_FOLDER):
            os.mkdir(self._configuration.GHIDRA_PROJECT_FOLDER)

        # Get the full path to the automation script
        analysis_script = os.path.join(os.getcwd(), GHIDRA_AUTOMATION_SCRIPT)

        # Run Ghidra
        ghidra_command = self._configuration.GHIDRA_COMMAND_FMT.format(
            self._filename, analysis_script).split(" ")
        try:
            process = subprocess.run(ghidra_command,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     check=True)
        except Exception:
            return None

        # Get the Ghidra's report and process it with a state machine logic
        analysis_report = process.stdout.decode("utf-8").splitlines()
        is_code_present = False
        are_calls_present = False
        for line in analysis_report:
            # If the report start is present, then start to read the decompiled
            # code
            if line.startswith(GHIDRA_REPORT_START_LINE):
                is_code_present = True
                continue

            # If the delimitor is not reached, then save the decompiled code
            if is_code_present:
                # If the delimitor is reached, start to read the calls
                if line.startswith(REPORT_DELIMITOR):
                    is_code_present = False
                    are_calls_present = True
                    continue

                self._decompiled_code += line + "\n"

                continue

            # Save the calls
            if are_calls_present:
                # If the end of the report is reached, then the rest of the
                # output is useless
                if line.startswith(GHIDRA_REPORT_FINISH_LINE):
                    break

                self._calls.add(line.strip())

        # Replace the Ghidra undefineds
        self._process_decompiled_code()

        # Mark the analysis as done
        self._was_ghidra_analyzed = True

    def detect_env(self) -> InputTypes:
        self._analyze_with_ghidra()

        self._input_types.environment_variables = self._have_element_in_common(
            self._calls, self._configuration.INPUT_INDICATOR_ENV)

        return self._input_types

    def detect_networking(self) -> InputTypes:
        self._analyze_with_ghidra()

        self._input_types.networking = self._have_element_in_common(
            self._calls, self._configuration.INPUT_INDICATOR_NETWORKING)

        return self._input_types

    def detect_stdin(self) -> InputTypes:
        self._analyze_with_ghidra()

        calls_of_interest = self._configuration.INPUT_INDICATOR_STDIN + self._configuration.INPUT_INDICATOR_FILES_STDIN
        self._input_types.stdin = self._have_element_in_common(
            self._calls, calls_of_interest)

        return self._input_types

    def detect_files(self) -> InputTypes:
        self._analyze_with_ghidra()

        # Check for operations with files. As some system calls can be used with
        # a file descriptor (that can identify the stdin too), the both call
        # types can marked as possible (the next module, the dynamic one, will
        # be activated for further analysis).
        self._input_types.files = self._have_element_in_common(
            self._calls, self._configuration.INPUT_INDICATOR_FILES_STDIN)

        return self._input_types

    def detect_arguments(self) -> InputTypes:
        self._analyze_with_ghidra()

        # Parse the C output from Ghidra
        parser = c_parser.CParser()
        ast = parser.parse(self._decompiled_code)

        # Get all the occurances of parameters
        visitor = ParametersCheckVisitor()
        visitor.visit(ast)

        # Set the usage of arguments
        self._input_types.arguments = visitor.are_parameters_used()

        return self._input_types

    def detect_all(self) -> InputTypes:
        self.detect_arguments()
        self.detect_env()
        self.detect_files()
        self.detect_networking()
        self.detect_stdin()

        return self._input_types
