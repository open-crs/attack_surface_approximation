import abc
import typing

from commons.arguments import ArgumentRole
from commons.arguments import ArgumentsPair as BaseArgumentsPair

QBDIAnalysisResult = typing.TypeVar("QBDIAnalysisResult")


class ArgumentsPair(BaseArgumentsPair):
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
            self.valid_roles.append(ArgumentRole.STRING_ENABLER)
