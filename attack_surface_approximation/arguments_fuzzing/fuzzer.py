import typing

from attack_surface_approximation.arguments_fuzzing.arguments_types import (
    ArgumentsPair,
)
from attack_surface_approximation.arguments_fuzzing.fuzzing_sequence_generator import (
    FuzzingSequenceGenerator,
)
from attack_surface_approximation.configuration import Configuration

from .qbdi_analysis import QBDIAnalysis

ANALYSIS_TIMEOUT = 3
CANARY_STRING = "string"
RANDOM_ARGUMENTS_COUNT = 10


class ArgumentsFuzzer:
    __configuration: object = Configuration.Fuzzer
    executable_filename: str
    dictionary: typing.List[str]
    analysis: QBDIAnalysis
    arguments_generator: FuzzingSequenceGenerator
    baseline_hashes: typing.List[str]
    old_hashes: typing.List[str]

    def __init__(
        self, executable_filename: str, dictionary: typing.List[str]
    ) -> None:
        self.executable_filename = executable_filename
        self.dictionary = dictionary

        self.analysis = QBDIAnalysis(
            executable_filename,
            ANALYSIS_TIMEOUT,
        )
        temp_filename = self.analysis.create_temp_file_inside_container()

        random_arguments_config = (
            self.__configuration.GENERATE_RANDOM_BASELINE_ARGUMENTS
        )
        self.arguments_generator = FuzzingSequenceGenerator(
            self.dictionary,
            temp_filename,
            CANARY_STRING,
            generate_random_baseline_arguments=random_arguments_config,
        )
        self.baseline_hashes = list(self.__generate_baseline_hashes())
        self.old_hashes = []

    def __generate_baseline_hashes(self) -> typing.Generator[str, None, None]:
        arguments = self.arguments_generator.generate_baseline_arguments(
            RANDOM_ARGUMENTS_COUNT
        )

        for argument in arguments:
            analysis_result = self.analysis.analyze(argument)

            yield analysis_result.bbs_hash

    def __check_if_argument_is_valid(
        self, argument: ArgumentsPair, result: QBDIAnalysis
    ) -> None:
        if (
            argument.get_roles_based_on_analysis(result, self.baseline_hashes)
            and result.bbs_hash not in self.old_hashes  # noqa: W503
        ):
            return True

        return False

    def get_valid_argument(
        self,
    ) -> typing.Generator[ArgumentsPair, None, None]:
        arguments = self.arguments_generator.generate_fuzzing_arguments(
            self.baseline_hashes
        )

        while True:
            try:
                argument = next(arguments)
            except StopIteration:
                break

            result = self.analysis.analyze(argument)

            if self.__check_if_argument_is_valid(argument, result):
                yield argument

            # Ensures the deduplication of --flag and --flag <string>. If the latter
            # generates a different hash than the baseline ones, it will be detected
            # as a false flag because of the sequence generation: --flag first, --flag
            # <string> afterwards.
            self.old_hashes.append(result.bbs_hash)

            self.arguments_generator.update_last_analysis_result(result)

    def get_all_valid_arguments(self) -> typing.List[ArgumentsPair]:
        return list(self.get_valid_argument())
