"""Module for implementing the QBDI analysis."""
import binascii
import os
import subprocess
import typing

from attack_surface_approximation.arguments_fuzzing.arguments import Argument

RANDOM_BYTES_COUNT = 128
QBDI_OUTPUT_FOLDER = "traces/"
CANARY_FILENAME = "canary.opencrs"
CANARY_STRING = "canary"
TIMEOUT = 5


class QBDIAnalysisResults:
    bbs_count: int
    bbs_hash: int
    uses_file: bool
    timeout: bool

    def __init__(
        self, bbs_count: int, bbs_hash: int, uses_file: bool, timeout: bool
    ) -> None:
        self.bbs_count = bbs_count
        self.bbs_hash = bbs_hash
        self.uses_file = uses_file
        self.timeout = timeout


class QBDIAnalysis:
    __process: subprocess.Popen
    analysis_name: str
    results: QBDIAnalysisResults

    def __init__(self, sut_name: str, arguments: Argument, stdin: str = None) -> None:
        environment = {"LD_BIND_NOW": "1", "LD_PRELOAD": "./libqbdi_tracer.so"}
        arguments = arguments.to_list()

        command_line = " ".join(arguments)
        self.analysis_name = binascii.hexlify(command_line).encode("utf-8")

        arguments.insert(0, sut_name)
        self.__process = subprocess.Popen(arguments, env=environment, stdin=stdin)

    @staticmethod
    def __parse_raw_output(filename: str) -> typing.Tuple[int, int, int]:
        with open(filename, "r", encoding="utf-8") as qbdi_output:
            analysis = qbdi_output.read()

            info = analysis.split(" ")
            info = [int(e) for e in info]

            return tuple(info)

    def __create_results(self, timeout: bool) -> QBDIAnalysisResults:
        qbdi_filaname = os.path.join(CANARY_FILENAME, self.analysis_name)
        bbs_count, bbs_hash, uses_file = self.__parse_raw_output(qbdi_filaname)

        return QBDIAnalysisResults(bbs_count, bbs_hash, uses_file, timeout)

    def wait(self) -> bool:
        timeout = False
        try:
            self.__process.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            self.__process.terminate()
            self.__process.wait()

            timeout = True
        finally:
            self.results = self.__create_results(timeout)
