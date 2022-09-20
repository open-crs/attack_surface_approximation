class Configuration:
    class GhidraDecompilation:
        FOLDER = "/home/iosifache/Documents/Resources/Programs/ghidra/"
        HEADLESS_ANALYZER = FOLDER + "support/analyzeHeadless"
        PROJECT_FOLDER = "/tmp/ghidra_projects/"
        PROJECT_NAME = "project"
        COMMAND_FMT = (
            HEADLESS_ANALYZER
            + " "
            + PROJECT_FOLDER
            + " "
            + PROJECT_NAME
            + " -import {} -overwrite -postscript {}"
        )

    class InputStreamsDetector:
        # At the moment, some libcalls and syscalls (for example, vfscanf) are
        # omitted due to an assumption that they are not frequently used in
        # practice. This list will anyway be continuously update
        INPUT_INDICATOR_ENV = ["getenv"]
        INPUT_INDICATOR_NETWORKING = ["recv", "recvfrom", "recvmsg"]
        INPUT_INDICATOR_FILES_STDIN = [
            "read",
            "pread",
            "fread",
            "fgets",
            "fgetc",
            "fscanf",
        ]
        INPUT_INDICATOR_STDIN = [
            "getc",
            "getchar",
            "gets",
            "scanf",
            "__isoc99_scanf",
        ]

    class QBDIAnalysis:
        IMAGE_TAG = "qbdi_args_fuzzing"
        HOST_FOLDER = "/tmp/qbdi/"
        HOST_DICTIONARIES_FOLDER = HOST_FOLDER + "dictionaries/"
        HOST_EXECUTABLE_FOLDER = HOST_FOLDER + "target/"
        HOST_EXECUTABLE = HOST_EXECUTABLE_FOLDER + "target"
        HOST_RESULTS_FOLDER = HOST_FOLDER + "results/"
        CONTAINER_EXECUTABLE_FOLDER = "/home/docker/target/"
        CONTAINER_EXECUTABLE = CONTAINER_EXECUTABLE_FOLDER + "target"
        CONTAINER_RESULTS_FOLDER = "/home/docker/results/"
        CONTAINER_TEMP_FILE = "/tmp/canary.opencrs"

    class Fuzzer:
        GENERATE_RANDOM_BASELINE_ARGUMENTS = False
