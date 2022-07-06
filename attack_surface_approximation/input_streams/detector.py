"""Module for implementing the approximation automation."""
import os
import typing

from elftools.elf.elffile import ELFError, ELFFile
from pycparser import c_parser

from attack_surface_approximation.configuration import Configuration
from attack_surface_approximation.exceptions import (ELFNotFoundException,
                                                     NotELFFileException)
from attack_surface_approximation.input_streams.ghidra_decompilation import \
    GhidraDecompilation

TEXT_SECTION_IDENTIFIER = ".text"
MAIN_FUNCTION_NAME = "main"
COMMENT_PREFIX = "/* WARNING"


class PresentInputStreams:
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
    __parameters_names: typing.List[str]
    __are_parameters_used: bool

    def __init__(self):
        self.__parameters_names = []
        self.__are_parameters_used = False

    def __check_parameters_used(self, obj: object) -> None:
        # Get all the attributes of the current object
        attrs = [
            attr
            for attr in dir(obj)
            if not callable(getattr(obj, attr)) and not attr.startswith("__")
        ]

        # Check if the "name" member appears here
        if "name" in attrs and getattr(obj, "name") in self.__parameters_names:
            self.__are_parameters_used = True

        # Call recursively the members of the object
        for attr in attrs:
            self.__check_parameters_used(attr)

    def are_parameters_used(self) -> bool:
        return self.__are_parameters_used

    def visit_ParamList(
        self, node: c_parser.c_ast.Node
    ):  # pylint: disable=invalid-name
        # Extract the parameters of the function
        self.__parameters_names = [parameter.name for parameter in node.params]

    def generic_visit(self, node: c_parser.c_ast.Node):
        # Check if the parameters are used in the current node
        self.__check_parameters_used(node)

        # Call the overwritten method
        super().generic_visit(node)


class InputStreamsDetector:
    __configuration: object = Configuration.InputStreamsDetector
    __filename: str
    __decompilation: GhidraDecompilation
    __input_types: PresentInputStreams

    def __init__(self, filename: str) -> None:
        if os.path.isfile(filename):
            # Check if the provided file is an ELF
            given_file = open(filename, "rb")
            try:
                ELFFile(given_file)
            except ELFError as exception:
                raise NotELFFileException() from exception

            self.__filename = filename
        else:
            raise ELFNotFoundException()

        self.__decompilation = GhidraDecompilation(self.__filename)
        self.__input_types = PresentInputStreams()

    @staticmethod
    def __have_element_in_common(first: set, second: set) -> True:
        if not (first and second):
            return False

        common_elements = [element for element in first if element in second]

        return len(common_elements) != 0

    def detect_env(self) -> PresentInputStreams:
        self.__input_types.environment_variables = self.__have_element_in_common(
            self.__decompilation.calls, self.__configuration.INPUT_INDICATOR_ENV
        )

        return self.__input_types

    def detect_networking(self) -> PresentInputStreams:
        self.__input_types.networking = self.__have_element_in_common(
            self.__decompilation.calls, self.__configuration.INPUT_INDICATOR_NETWORKING
        )

        return self.__input_types

    def detect_stdin(self) -> PresentInputStreams:
        calls_of_interest = (
            self.__configuration.INPUT_INDICATOR_STDIN
            + self.__configuration.INPUT_INDICATOR_FILES_STDIN
        )
        self.__input_types.stdin = self.__have_element_in_common(
            self.__decompilation.calls, calls_of_interest
        )

        return self.__input_types

    def detect_files(self) -> PresentInputStreams:
        # Check for operations with files. As some system calls can be used with
        # a file descriptor (that can identify the stdin too), the both call
        # types can marked as possible (the next module, the dynamic one, will
        # be activated for further analysis).
        self.__input_types.files = self.__have_element_in_common(
            self.__decompilation.calls, self.__configuration.INPUT_INDICATOR_FILES_STDIN
        )

        return self.__input_types

    def detect_arguments(self) -> PresentInputStreams:
        # Parse the C output from Ghidra
        parser = c_parser.CParser()
        ast = parser.parse(self.__decompilation.decompiled_code)

        # Get all the occurances of parameters
        visitor = ParametersCheckVisitor()
        visitor.visit(ast)

        # Set the usage of arguments
        self.__input_types.arguments = visitor.are_parameters_used()

        return self.__input_types

    def detect_all(self) -> PresentInputStreams:
        self.detect_arguments()
        self.detect_env()
        self.detect_files()
        self.detect_networking()
        self.detect_stdin()

        return self.__input_types
