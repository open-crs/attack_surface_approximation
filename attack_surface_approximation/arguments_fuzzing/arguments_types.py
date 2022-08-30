import abc
import typing
from enum import Enum

QBDIAnalysisResult = typing.TypeVar("QBDIAnalysisResult")


class ArgumentRole(Enum):
    FLAG = 0
    STDIN_ENABLER = 1
    FILE_ENABLER = 2
    STRING_ENABLER = 3

    def __str__(self) -> str:
        return self.name


class ArgumentsPair:
    first: str
    second: str
    valid_roles: typing.List[ArgumentRole]

    def __init__(self) -> None:
        self.first = None
        self.second = None
        self.valid_roles = []

    @abc.abstractmethod
    def attach_roles_based_on_analysis(
        self, result: QBDIAnalysisResult, bbs_hashes_baseline: typing.List[str]
    ) -> None:
        raise NotImplementedError()

    def get_roles_based_on_analysis(
        self, result: QBDIAnalysisResult, bbs_hashes_baseline: typing.List[str]
    ) -> typing.List[ArgumentRole]:
        self.attach_roles_based_on_analysis(result, bbs_hashes_baseline)

        return self.valid_roles

    def to_str(self) -> str:
        if not self.first:
            return ""
        elif not self.second:
            return self.first
        else:
            return f"{self.first} {self.second}"

    def to_hex_id(self) -> str:
        if not self.first:
            return "none"

        return self.to_str().encode("utf-8").hex().upper()


class NoneArgument(ArgumentsPair):
    first: typing.Optional[str] = None
    second: typing.Optional[str] = None

    def attach_roles_based_on_analysis(  # pylint: disable=unused-private-member
        self, result: QBDIAnalysisResult, bbs_hashes_baseline: typing.List[str]
    ) -> None:
        if result.uses_stdin:
            self.valid_roles.append(ArgumentRole.STDIN_ENABLER)


class FileArgument(ArgumentsPair):
    def __init__(self, filename: str) -> None:
        super().__init__()

        self.first = filename

    def attach_roles_based_on_analysis(  # pylint: disable=unused-private-member
        self, result: QBDIAnalysisResult, bbs_hashes_baseline: typing.List[str]
    ) -> None:
        if result.uses_file:
            self.valid_roles.append(ArgumentRole.FILE_ENABLER)


class ArgumentPlusFileArgument(ArgumentsPair):
    def __init__(self, argument: str, filename: str) -> None:
        super().__init__()

        self.first = argument
        self.second = filename

    def attach_roles_based_on_analysis(  # pylint: disable=unused-private-member
        self, result: QBDIAnalysisResult, bbs_hashes_baseline: typing.List[str]
    ) -> None:
        if result.uses_file:
            self.valid_roles.append(ArgumentRole.FILE_ENABLER)


class ArgumentArgument(ArgumentsPair):
    def __init__(self, argument: str) -> None:
        super().__init__()

        self.first = argument

    def attach_roles_based_on_analysis(  # pylint: disable=unused-private-member
        self, result: QBDIAnalysisResult, bbs_hashes_baseline: typing.List[str]
    ) -> None:
        if result.uses_stdin:
            self.valid_roles.append(ArgumentRole.STDIN_ENABLER)
        if result.bbs_hash not in bbs_hashes_baseline:
            self.valid_roles.append(ArgumentRole.FLAG)


class ArgumentStringArgument(ArgumentsPair):
    def __init__(self, argument: str, text: str) -> None:
        super().__init__()

        self.first = argument
        self.second = text

    def attach_roles_based_on_analysis(  # pylint: disable=unused-private-member
        self, result: QBDIAnalysisResult, bbs_hashes_baseline: typing.List[str]
    ) -> None:
        if result.bbs_hash not in bbs_hashes_baseline:
            self.valid_roles.append(ArgumentRole.STRING_ENABLER)
