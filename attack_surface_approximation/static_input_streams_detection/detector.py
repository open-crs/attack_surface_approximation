import os
import typing

from elftools.elf.elffile import ELFError, ELFFile
from pycparser import c_parser

from attack_surface_approximation.configuration import Configuration
from attack_surface_approximation.exceptions import (
    ELFNotFoundException,
    NotELFFileException,
)
from commons.ghidra import GhidraAnalysis
from commons.input_streams import InputStreams

TEXT_SECTION_IDENTIFIER = ".text"
MAIN_FUNCTION_NAME = "main"
COMMENT_PREFIX = "/* WARNING"


class ParametersCheckVisitor(c_parser.c_ast.NodeVisitor):
    __parameters_names: typing.List[str]
    __are_parameters_used: bool

    def __init__(self) -> None:
        self.__parameters_names = []
        self.__are_parameters_used = False

    def __check_parameters_used(self, obj: object) -> None:
        attrs = [
            attr
            for attr in dir(obj)
            if not callable(getattr(obj, attr)) and not attr.startswith("__")
        ]

        if "name" in attrs and getattr(obj, "name") in self.__parameters_names:
            self.__are_parameters_used = True

        for attr in attrs:
            self.__check_parameters_used(attr)

    def are_parameters_used(self) -> bool:
        return self.__are_parameters_used

    def visit_ParamList(  # pylint: disable=invalid-name
        self, node: c_parser.c_ast.Node
    ) -> None:  # pylint: disable=invalid-name
        self.__parameters_names = [parameter.name for parameter in node.params]

        self.__check_void_arglist()

    def __check_void_arglist(self) -> None:
        if (
            len(self.__parameters_names) == 1
            and self.__parameters_names[0] is None
        ):
            self.__parameters_names = []

    def generic_visit(self, node: c_parser.c_ast.Node) -> None:
        self.__check_parameters_used(node)

        super().generic_visit(node)


class InputStreamsDetector:
    __filename: str
    __calls: typing.List[str]
    __main_decompilation: str

    def __init__(self, filename: str) -> None:
        if os.path.isfile(filename):
            given_file = open(filename, "rb")
            try:
                ELFFile(given_file)
            except ELFError as exception:
                raise NotELFFileException() from exception

            self.__filename = filename
        else:
            raise ELFNotFoundException()

        analysis = GhidraAnalysis(self.__filename)
        self.__calls = list(analysis.extract_calls())
        self.__main_decompilation = analysis.decompile_function("main")

    @staticmethod
    def __have_element_in_common(first: set, second: set) -> True:
        if not (first and second):
            return False

        common_elements = [element for element in first if element in second]

        return len(common_elements) != 0

    def uses_env(self) -> bool:
        return self.__have_element_in_common(
            self.__calls, InputStreams.ENVIRONMENT_VARIABLE.value.indicators
        )

    def uses_networking(self) -> bool:
        return self.__have_element_in_common(
            self.__calls, InputStreams.NETWORKING.value.indicators
        )

    def uses_stdin(self) -> bool:
        return self.__have_element_in_common(
            self.__calls, InputStreams.STDIN.value.indicators
        )

    def uses_files(self) -> bool:
        # As some system calls can be used with a file descriptor (that can identify
        # the stdin too), the both call types can marked as possible (the next module,
        # the dynamic one, will be activated for further analysis).
        return self.__have_element_in_common(
            self.__calls, InputStreams.FILES.value.indicators
        )

    def uses_arguments(self) -> bool:
        parser = c_parser.CParser()
        ast = parser.parse(self.__main_decompilation)

        visitor = ParametersCheckVisitor()
        visitor.visit(ast)

        return visitor.are_parameters_used()

    def __detect_all(self) -> typing.Generator[InputStreams, None, None]:
        if self.uses_env():
            yield InputStreams.ENVIRONMENT_VARIABLE

        if self.uses_arguments():
            yield InputStreams.ARGUMENTS

        if self.uses_files():
            yield InputStreams.FILES

        if self.uses_stdin():
            yield InputStreams.STDIN

        if self.uses_networking():
            yield InputStreams.NETWORKING

    def detect_all(self) -> typing.List[InputStreams]:
        return list(self.__detect_all())
