"""Module for storing types of arguments."""
import abc
import typing
from enum import Enum

from attack_surface_approximation.arguments_fuzzing.qbdi_analysis import (
    QBDIAnalysisResults,
)


class ArgumentRole(Enum):
    FLAG = 0
    STDIN_ENABLER = 1
    FILE_ENABLER = 2
    STRING_ENABLER = 3


class Argument:
    first: str
    second: str
    valid_roles: typing.List[ArgumentRole]
    results: QBDIAnalysisResults

    def __init__(self):
        self.valid_roles = []

    def to_list(self) -> typing.List[str]:
        return [self.first, self.second]

    def set_results(self, results: QBDIAnalysisResults) -> None:
        self.results = results

    def _is_timeout_stdin(self) -> bool:
        pass

    @abc.abstractmethod
    def validate(self, bbs_hash_baseline: str) -> None:
        raise NotImplementedError()


class NoneArgument(Argument):
    first: typing.Optional[str] = None
    second: typing.Optional[str] = None

    def validate(self, bbs_hash_baseline: str) -> None:
        if self.results.timeout and self._is_timeout_stdin():
            self.valid_roles.append(ArgumentRole.STDIN_ENABLER)


class FileArgument(Argument):
    def __init__(self, filename: str) -> None:
        super().__init__()

        self.first = filename

    def validate(self, bbs_hash_baseline: str) -> None:
        if self.results.uses_file:
            self.valid_roles.append(ArgumentRole.FILE_ENABLER)


class ArgumentPlusFileArgument(Argument):
    def __init__(self, argument: str, filename: str) -> None:
        super().__init__()

        self.first = argument
        self.second = filename

    def validate(self, bbs_hash_baseline: str) -> None:
        if self.results.uses_file:
            self.valid_roles.append(ArgumentRole.FILE_ENABLER)


class ArgumentArgument(Argument):
    def __init__(self, argument: str) -> None:
        super().__init__()

        self.first = argument

    def validate(self, bbs_hash_baseline: str) -> None:
        if self.results.timeout and self._is_timeout_stdin():
            self.valid_roles.append(ArgumentRole.STDIN_ENABLER)
        if self.results.bbs_hash != bbs_hash_baseline:
            self.valid_roles.append(ArgumentRole.FLAG)


class ArgumentStringArgument(Argument):
    def __init__(self, argument: str, string: str) -> None:
        super().__init__()

        self.first = argument
        self.second = string

    def validate(self, bbs_hash_baseline: str) -> None:
        if self.results.bbs_hash != bbs_hash_baseline:
            self.valid_roles.append(ArgumentRole.STRING_ENABLER)
