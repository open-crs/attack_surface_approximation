import os
import shutil
import stat
import typing

import docker
from docker.models.containers import ExecResult

from attack_surface_approximation.arguments_fuzzing.arguments_types import (
    ArgumentsPair,
)
from attack_surface_approximation.configuration import Configuration


class RawQBDIAnalysisResult:
    bbs_count: int
    bbs_hash: int
    uses_file: bool
    exit_code: int

    def __init__(
        self, bbs_count: int, bbs_hash: int, uses_file: bool, exit_code: int
    ) -> None:
        self.bbs_count = bbs_count
        self.bbs_hash = bbs_hash
        self.uses_file = uses_file
        self.exit_code = exit_code


class QBDIAnalysisResult(RawQBDIAnalysisResult):
    uses_stdin: bool

    def __init__(
        self,
        bbs_count: int,
        bbs_hash: int,
        uses_file: bool,
        exit_code: int,
        uses_stdin: bool,
    ) -> None:
        super().__init__(bbs_count, bbs_hash, uses_file, exit_code)

        self.uses_stdin = uses_stdin


class QBDIAnalysis:
    __configuration: object = Configuration.QBDIAnalysis
    __docker_client: docker.client
    __container: docker.api.container
    executable_filename: str
    timeout: int

    def __init__(self, executable_filename: str, timeout: int) -> None:
        self.executable_filename = executable_filename
        self.timeout = timeout

        self.__docker_client = docker.from_env()
        self.__create_container()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__container.remove(force=True)
        return False

    def __touch_nested_folder(self, folder_name: str) -> None:
        try:
            os.makedirs(folder_name)
        except FileExistsError:
            shutil.rmtree(folder_name)
            os.makedirs(folder_name)

    def __create_temporary_folder_structure(self) -> None:
        self.__touch_nested_folder(self.__configuration.HOST_FOLDER)
        self.__touch_nested_folder(self.__configuration.HOST_EXECUTABLE_FOLDER)
        self.__touch_nested_folder(self.__configuration.HOST_RESULTS_FOLDER)
        shutil.copyfile(
            self.executable_filename, self.__configuration.HOST_EXECUTABLE
        )
        os.chmod(self.__configuration.HOST_EXECUTABLE, stat.S_IXUSR)

    def __create_container(self) -> None:
        self.__create_temporary_folder_structure()

        template = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "qbdi_analysis_scripts/qbdi_preload_template.c",
        )
        header = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "qbdi_analysis_scripts/utarray.h",
        )
        enforcer = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "qbdi_analysis_scripts/determinism_enforcer.c",
        )
        self.__container = self.__docker_client.containers.run(
            self.__configuration.IMAGE_TAG,
            command="tail -f /dev/null",
            detach=True,
            tty=True,
            volumes={
                self.__configuration.HOST_EXECUTABLE_FOLDER: {
                    "bind": self.__configuration.CONTAINER_EXECUTABLE_FOLDER,
                    "mode": "rw",
                },
                self.__configuration.HOST_RESULTS_FOLDER: {
                    "bind": self.__configuration.CONTAINER_RESULTS_FOLDER,
                    "mode": "rw",
                },
                template: {
                    "bind": os.path.join(
                        self.__configuration.CONTAINER_SO_FOLDER,
                        "qbdi_preload_template.c",
                    ),
                    "mode": "rw",
                },
                header: {
                    "bind": os.path.join(
                        self.__configuration.CONTAINER_SO_FOLDER, "utarray.h"
                    ),
                    "mode": "rw",
                },
                enforcer: {
                    "bind": os.path.join(
                        self.__configuration.CONTAINER_SO_FOLDER,
                        "determinism_enforcer.c",
                    ),
                    "mode": "rw",
                },
            },
        )

        self.__container.exec_run(
            f"sudo chmod 555 {self.__configuration.CONTAINER_EXECUTABLE}"
        )

        # Ensure the results directory is writable by everyone
        self.__container.exec_run(
            f"mkdir -p {self.__configuration.CONTAINER_RESULTS_FOLDER}"
        )
        self.__container.exec_run(
            f"sudo chmod 1777 {self.__configuration.CONTAINER_RESULTS_FOLDER}"
        )

        self.__container.exec_run(
            "rm -f CMakeCache.txt libqbdi_tracer.so",
            workdir=self.__configuration.CONTAINER_SO_FOLDER,
        )
        self.__run_build_command("cmake .")
        self.__run_build_command("make")
        self.__run_build_command(
            "gcc -shared -fPIC -m32 -o libdet_enforcer.so determinism_enforcer.c -ldl"
        )

    def __run_build_command(self, command: str) -> None:
        result = self.__container.exec_run(
            command, workdir=self.__configuration.CONTAINER_SO_FOLDER
        )
        if result.exit_code != 0:
            raise RuntimeError(
                f"Command '{command}' failed inside the QBDI container "
                f"(exit code {result.exit_code}): "
                f"{result.output.decode(errors='replace')}"
            )

    def produces_stderr(self, argument: ArgumentsPair) -> bool:
        stringified_arguments = argument.to_str()
        result = self.__container.exec_run(
            f"timeout {self.timeout} {self.__configuration.CONTAINER_EXECUTABLE} {stringified_arguments}",
            workdir="/home/docker",
            demux=True,
        )
        _, stderr = result.output
        return bool(stderr)

    def create_temp_file_inside_container(self) -> str:
        self.__container.exec_run(
            f"touch {self.__configuration.CONTAINER_TEMP_FILE}"
        )

        return self.__configuration.CONTAINER_TEMP_FILE

    def __build_and_run_analyze_command(
        self, argument: ArgumentsPair, timeout_retry: bool, set_hash_mode: bool = False
    ) -> ExecResult:
        command = self.__build_analyze_command(argument, timeout_retry, set_hash_mode)

        return self.__container.exec_run(
            command,
            workdir="/home/docker",
            tty=True,
        )

    def __build_analyze_command(
        self, argument: ArgumentsPair, timeout_retry: bool, set_hash_mode: bool = False
    ) -> str:
        stringified_arguments = argument.to_str()
        stdin_avoidance_command = "echo '\n' |" if timeout_retry else ""
        use_set_hash = "USE_SET_HASH=1 " if set_hash_mode else ""

        return (
            f"timeout {self.timeout} sh -c "
            f"'{stdin_avoidance_command} LD_BIND_NOW=1 "
            "LD_PRELOAD=./libdet_enforcer.so:./libqbdi_tracer.so "
            f"{use_set_hash}"
            f"{self.__configuration.CONTAINER_EXECUTABLE} "
            f"{stringified_arguments}'"
        )

    def __get_analysis_result_filename(self, argument: ArgumentsPair) -> str:
        argument_identifier = argument.to_hex_id()

        return os.path.join(
            self.__configuration.HOST_RESULTS_FOLDER, argument_identifier
        )

    @staticmethod
    def __parse_raw_output(filename: str) -> typing.Tuple[int, int, int]:
        try:
            with open(filename, "r", encoding="utf-8") as qbdi_output:
                analysis = qbdi_output.read()

                info = analysis.split(" ")
                info = [int(e) for e in info]

                return tuple(info)
        except FileNotFoundError:
            return (None, None, None)

    def __run_analysis(
        self, argument: ArgumentsPair, timeout_retry: bool = False, set_hash_mode: bool = False
    ) -> RawQBDIAnalysisResult:
        raw_result = self.__build_and_run_analyze_command(
            argument, timeout_retry, set_hash_mode
        )

        # Ensure the result file is readable by the host user
        argument_identifier = argument.to_hex_id()
        result_path = os.path.join(
            self.__configuration.CONTAINER_RESULTS_FOLDER, argument_identifier
        )
        self.__container.exec_run(f"test -f {result_path} && chmod 644 {result_path}")

        result_filename = self.__get_analysis_result_filename(argument)
        bbs_count, bbs_hash, uses_file = self.__parse_raw_output(
            result_filename
        )

        return RawQBDIAnalysisResult(
            bbs_count, bbs_hash, uses_file, raw_result.exit_code
        )

    def __detect_stdin_usage(
        self,
        argument: ArgumentsPair,
        raw_analysis: RawQBDIAnalysisResult,
        timeout_retry: bool,
        set_hash_mode: bool = False,
    ) -> bool:
        is_timeout = raw_analysis.exit_code == 124
        if timeout_retry and not is_timeout:
            return True
        elif not timeout_retry and is_timeout:
            return self.analyze(argument, timeout_retry=True, set_hash_mode=set_hash_mode).uses_stdin
        else:
            return False

    def analyze(
        self, argument: ArgumentsPair, timeout_retry: bool = False, set_hash_mode: bool = False
    ) -> QBDIAnalysisResult:
        raw_analysis = self.__run_analysis(argument, timeout_retry, set_hash_mode)
        uses_stdin = self.__detect_stdin_usage(
            argument,
            raw_analysis,
            timeout_retry,
            set_hash_mode,
        )

        return QBDIAnalysisResult(
            raw_analysis.bbs_count,
            raw_analysis.bbs_hash,
            raw_analysis.uses_file,
            raw_analysis.exit_code,
            uses_stdin,
        )
