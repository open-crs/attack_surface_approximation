import os
import subprocess
import typing

from attack_surface_approximation.configuration import Configuration

COMMENT_PREFIX = "/* WARNING"
AUTOMATION_SCRIPT = (
    "attack_surface_approximation/"
    "static_input_streams_detection/ghidra_automation.py"
)
REPORT_START_LINE = "INFO  SCRIPT"
REPORT_FINISH_LINE = "INFO  ANALYZING"
REPORT_DELIMITOR = 16 * "*"


class GhidraDecompilation:
    __configuration = Configuration.GhidraDecompilation
    decompiled_code: str
    calls: typing.Set[str]

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.decompiled_code = ""
        self.calls = set()

        self.__ensure_project_folder()
        self.__analyze_with_ghidra()

    def __ensure_project_folder(self) -> None:
        if not os.path.isdir(self.__configuration.PROJECT_FOLDER):
            os.mkdir(self.__configuration.PROJECT_FOLDER)

    def __analyze_with_ghidra(self) -> None:
        analysis_report = self.__run_ghidra()

        self.__process_analysis_report(analysis_report)

    def __run_ghidra(self) -> typing.List[str]:
        analysis_script = os.path.join(os.getcwd(), AUTOMATION_SCRIPT)

        ghidra_command = self.__configuration.COMMAND_FMT.format(
            self.filename, analysis_script
        ).split(" ")
        try:
            process = subprocess.run(
                ghidra_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

            return process.stdout.decode("utf-8").splitlines()
        except subprocess.CalledProcessError:
            return None

    def __process_analysis_report(
        self, analysis_report: typing.List[str]
    ) -> None:
        is_code_present = False
        are_calls_present = False
        for line in analysis_report:
            if line.startswith(REPORT_START_LINE):
                is_code_present = True
                continue

            if is_code_present:
                if line.startswith(REPORT_DELIMITOR):
                    is_code_present = False
                    are_calls_present = True
                    continue

                self.decompiled_code += line + "\n"

                continue

            if are_calls_present:
                if line.startswith(REPORT_FINISH_LINE):
                    break

                self.calls.add(self.__preprocess_call(line.strip()))

        self.__process_decompiled_code()

    def __preprocess_call(self, call: str) -> str:
        if "::" in call:
            return call.split("::")[1]
        else:
            return call

    def __process_decompiled_code(self) -> None:
        self.__replace_undefs()
        self.__replace_longs()
        self.__replace_double_lines()
        self.__replace_comments_for_pycparser()

    def __replace_undefs(self) -> None:
        self.decompiled_code = self.decompiled_code.replace(
            "undefined4", "int"
        ).replace("undefined", "char")

    def __replace_longs(self) -> None:
        self.decompiled_code = self.decompiled_code.replace("char8", "long")

    def __replace_double_lines(self) -> None:
        self.decompiled_code = self.decompiled_code.replace("\n\n", "\n")

    def __replace_comments_for_pycparser(self) -> None:
        # pycparser won't be able to parse lines with comments.
        no_comments_code = []
        for line in self.decompiled_code.splitlines():
            if COMMENT_PREFIX not in line:
                no_comments_code.append(line)
        self.decompiled_code = "\n".join(no_comments_code)
