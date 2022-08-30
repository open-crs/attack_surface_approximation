import random
import string
import typing

from attack_surface_approximation.arguments_fuzzing.arguments_types import (
    ArgumentArgument,
    ArgumentPlusFileArgument,
    ArgumentRole,
    ArgumentsPair,
    ArgumentStringArgument,
    FileArgument,
    NoneArgument,
)
from attack_surface_approximation.arguments_fuzzing.qbdi_analysis import (
    QBDIAnalysisResult,
)

ArgumentsGenerator = typing.Generator[ArgumentsPair, None, None]


class FuzzingSequenceGenerator:
    arguments: typing.List[str]
    canary_filename: str
    canary_string: str
    last_analysis_result: str
    generate_random_baseline_arguments: bool

    def __init__(
        self,
        arguments: typing.List[str],
        canary_filename: str,
        canary_string: str,
        generate_random_baseline_arguments: bool = False,
    ) -> None:
        self.canary_filename = canary_filename
        self.arguments = arguments
        self.canary_string = canary_string
        self.generate_random_baseline_arguments = generate_random_baseline_arguments

    def update_last_analysis_result(
        self, last_analysis_result: QBDIAnalysisResult
    ) -> None:
        self.last_analysis_result = last_analysis_result

    def __generate_usual_help_arguments(self) -> ArgumentsGenerator:
        for arg in ["-h", "--help"]:
            yield ArgumentArgument(arg)

    def __generate_invalid_arguments(self, length: int) -> ArgumentsGenerator:
        for dashes_count in [1, 2]:
            arg_preffix = dashes_count * "-"

            for _ in range(0, length):
                text = "".join(
                    [random.choice(string.ascii_lowercase) for _ in range(0, 10)]
                )

                yield ArgumentArgument(arg_preffix + text)

    def generate_baseline_arguments(
        self, invalid_arguments_length: int
    ) -> ArgumentsGenerator:
        yield NoneArgument()
        yield from self.__generate_usual_help_arguments()

        if self.generate_random_baseline_arguments:
            yield from self.__generate_invalid_arguments(invalid_arguments_length)

    def generate_fuzzing_arguments(
        self, bbs_hashes_baseline: typing.List[str]
    ) -> ArgumentsGenerator:
        arg = FileArgument(self.canary_filename)
        yield arg
        if ArgumentRole.FILE_ENABLER not in arg.get_roles_based_on_analysis(
            self.last_analysis_result, bbs_hashes_baseline
        ):
            for argument in self.arguments:
                yield ArgumentPlusFileArgument(argument, self.canary_filename)

        yield ArgumentArgument("-")

        yield NoneArgument()

        for argument in self.arguments:
            yield ArgumentArgument(argument)
            yield ArgumentStringArgument(argument, self.canary_string)
