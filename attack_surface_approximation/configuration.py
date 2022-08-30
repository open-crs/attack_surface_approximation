class Configuration:
    class GhidraDecompilation:
        # Folders
        GHIDRA_FOLDER = "/home/iosifache/Documents/Resources/Programs/ghidra/"
        GHIDRA_HEADLESS_ANALYZER = GHIDRA_FOLDER + "support/analyzeHeadless"
        GHIDRA_PROJECT_FOLDER = "/tmp/ghidra_projects/"

        # Miscellaneous
        GHIDRA_PROJECT_NAME = "project"
        GHIDRA_COMMAND_FMT = (
            GHIDRA_HEADLESS_ANALYZER
            + " "
            + GHIDRA_PROJECT_FOLDER
            + " "
            + GHIDRA_PROJECT_NAME
            + " -import {} -overwrite -postscript {}"
        )

    class InputStreamsDetector:
        # Relevant function calls
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