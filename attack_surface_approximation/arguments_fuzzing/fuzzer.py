import typing

from attack_surface_approximation.arguments_fuzzing.arguments_types import (
    ArgumentsPair,
    ArgumentStringArgument,
    NoneArgument,
)
from commons.arguments import ArgumentRole
from attack_surface_approximation.arguments_fuzzing.fuzzing_sequence_generator import (
    FuzzingSequenceGenerator,
)
from attack_surface_approximation.configuration import Configuration

from .qbdi_analysis import QBDIAnalysis, QBDIAnalysisResult

ANALYSIS_TIMEOUT = 3
CANARY_STRING = "string"
CANARY_STRING_ALTERNATIVE = "alternative"
RANDOM_ARGUMENTS_COUNT = 10


class ArgumentsFuzzer:
    __configuration: object = Configuration.Fuzzer
    executable_filename: str
    dictionary: typing.List[str]
    analysis: QBDIAnalysis
    arguments_generator: FuzzingSequenceGenerator
    baseline_hashes: typing.List[str]
    old_hashes: typing.List[str]
    baseline_uses_stdin: bool
    baseline_uses_file: bool
    is_nondeterministic: bool

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
        self.baseline_uses_stdin = False
        self.baseline_uses_file = False
        self.baseline_hashes = self.__generate_baseline_hashes()
        self.old_hashes = []
        self.is_nondeterministic = self.__detect_nondeterminism()
        if self.is_nondeterministic:
            self.baseline_hashes = self.__generate_baseline_hashes(set_hash_mode=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.analysis.__exit__(exc_type, exc_val, exc_tb)

    def __generate_baseline_hashes(self, set_hash_mode: bool = False) -> typing.List[str]:
        arguments = self.arguments_generator.generate_baseline_arguments(
            RANDOM_ARGUMENTS_COUNT
        )

        hashes = []
        first = True

        for argument in arguments:
            analysis_result = self.analysis.analyze(argument, set_hash_mode=set_hash_mode)

            if analysis_result.bbs_hash is not None:
                hashes.append(analysis_result.bbs_hash)
            if first:
                self.baseline_uses_stdin = analysis_result.uses_stdin
                self.baseline_uses_file = analysis_result.uses_file
                first = False

        return hashes

    def __detect_nondeterminism(self) -> bool:
        arg = NoneArgument()
        r1 = self.analysis.analyze(arg)
        r2 = self.analysis.analyze(arg)
        if r1.bbs_hash is None or r2.bbs_hash is None:
            return False
        return r1.bbs_hash != r2.bbs_hash
                

    def __check_if_argument_is_valid(
        self, argument: ArgumentsPair, result: QBDIAnalysisResult
    ) -> bool:
        if result.bbs_hash is None:
            return False

        if (
            argument.get_roles_based_on_analysis(result, self.baseline_hashes)
            and result.bbs_hash not in self.old_hashes  # noqa: W503
        ):
            return True

        return False

    def __get_valid_argument(
        self,
    ) -> typing.Generator[ArgumentsPair, None, None]:
        arguments = self.arguments_generator.generate_fuzzing_arguments(
            self.baseline_hashes
        )

        result = None
        while True:
            try:
                argument = (
                    arguments.send(result) if result is not None else next(arguments)
                )
            except StopIteration:
                break

            result = self.analysis.analyze(argument, set_hash_mode=self.is_nondeterministic)

            if self.__check_if_argument_is_valid(argument, result):
                yield argument

            # Deduplicates arguments with identical execution hashes (e.g. -v and --verbose).
            # Also short-circuits STRING_ENABLER candidates where hash(flag, string) == hash(flag),
            # avoiding two extra QBDI runs otherwise handled by __ignores_string_value.
            if result.bbs_hash is not None:
                self.old_hashes.append(result.bbs_hash)

    # Filters arguments that cause the binary to write to stderr — binary actively rejects them.
    def __produces_stderr(self, argument: ArgumentsPair) -> bool:
        if ArgumentRole.FLAG not in argument.valid_roles and ArgumentRole.STRING_ENABLER not in argument.valid_roles:
            return False
        return self.analysis.produces_stderr(argument)

    # Detects STRING_ENABLERs where the string value is irrelevant: runs with two different
    # canary strings and compares hashes — equal hashes mean the string is ignored by the binary.
    def __ignores_string_value(self, argument: ArgumentsPair) -> bool:
        if ArgumentRole.STRING_ENABLER not in argument.valid_roles:
            return False

        r1 = self.analysis.analyze(ArgumentStringArgument(argument.first, CANARY_STRING), set_hash_mode=self.is_nondeterministic)
        r2 = self.analysis.analyze(ArgumentStringArgument(argument.first, CANARY_STRING_ALTERNATIVE), set_hash_mode=self.is_nondeterministic)
        
        return (
            r1.bbs_hash is not None
            and r2.bbs_hash is not None
            and r1.bbs_hash == r2.bbs_hash
        )

    # Binary blocks on stdin regardless of any flag — flag didn't enable stdin reading.
    def __reads_stdin_regardless(self, argument: ArgumentsPair) -> bool:
        if ArgumentRole.STDIN_ENABLER not in argument.valid_roles:
            return False
        return self.baseline_uses_stdin

    # Binary opens files regardless of any flag — flag didn't enable file access.
    def __opens_files_regardless(self, argument: ArgumentsPair) -> bool:
        if ArgumentRole.FILE_ENABLER not in argument.valid_roles:
            return False
        return self.baseline_uses_file

    def get_all_valid_arguments(self) -> typing.List[ArgumentsPair]:
        candidates = list(self.__get_valid_argument())
        return [
            a for a in candidates
            if not self.__produces_stderr(a)
            and not self.__ignores_string_value(a)
            and not self.__reads_stdin_regardless(a)
            and not self.__opens_files_regardless(a)
        ]