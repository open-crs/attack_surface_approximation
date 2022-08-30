import os
import subprocess
import typing

from attack_surface_approximation.configuration import Configuration

COMMENT_PREFIX = "/* WARNING"
GHIDRA_AUTOMATION_SCRIPT = (
    "attack_surface_approximation/"
    "static_input_streams_detection/ghidra_automation.py"
)
GHIDRA_REPORT_START_LINE = "INFO  SCRIPT"
GHIDRA_REPORT_FINISH_LINE = "INFO  ANALYZING"
REPORT_DELIMITOR = 16 * "*"


class GhidraDecompilation:
    __configuration = Configuration.GhidraDecompilation
    decompiled_code: str
    calls: typing.Set[str]

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.decompiled_code = ""
        self.calls = set()

        self.__analyze_with_ghidra()

    def __process_decompiled_code(self) -> None:
        # Replace undefs
        self.decompiled_code = self.decompiled_code.replace(
            "undefined4", "int"
        ).replace("undefined", "char")

        # Replace with longs
        self.decompiled_code = self.decompiled_code.replace("char8", "long")

        # Replace useless double line
        self.decompiled_code = self.decompiled_code.replace("\n\n", "\n")

        # Skip a line containing a comment. pycparser won't be able to
        # parse it.
        no_comments_code = []
        for line in self.decompiled_code.splitlines():
            if COMMENT_PREFIX not in line:
                no_comments_code.append(line)
        self.decompiled_code = "\n".join(no_comments_code)

    def __analyze_with_ghidra(self) -> None:
        # Ensure that the project folder is created
        if not os.path.isdir(self.__configuration.GHIDRA_PROJECT_FOLDER):
            os.mkdir(self.__configuration.GHIDRA_PROJECT_FOLDER)

        # Get the full path to the automation script
        analysis_script = os.path.join(os.getcwd(), GHIDRA_AUTOMATION_SCRIPT)

        # Run Ghidra
        ghidra_command = self.__configuration.GHIDRA_COMMAND_FMT.format(
            self.filename, analysis_script
        ).split(" ")
        try:
            process = subprocess.run(
                ghidra_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError:
            return None

        # Get the Ghidra's report and process it with a state machine logic
        analysis_report = process.stdout.decode("utf-8").splitlines()
        is_code_present = False
        are_calls_present = False
        for line in analysis_report:
            # If the report start is present, then start to read the decompiled
            # code
            if line.startswith(GHIDRA_REPORT_START_LINE):
                is_code_present = True
                continue

            # If the delimitor is not reached, then save the decompiled code
            if is_code_present:
                # If the delimitor is reached, start to read the calls
                if line.startswith(REPORT_DELIMITOR):
                    is_code_present = False
                    are_calls_present = True
                    continue

                self.decompiled_code += line + "\n"

                continue

            # Save the calls
            if are_calls_present:
                # If the end of the report is reached, then the rest of the
                # output is useless
                if line.startswith(GHIDRA_REPORT_FINISH_LINE):
                    break

                self.calls.add(line.strip())

        # Replace the Ghidra undefineds
        self.__process_decompiled_code()
