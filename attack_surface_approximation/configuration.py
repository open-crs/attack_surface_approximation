class Configuration:
    class Fuzzer:
        GENERATE_RANDOM_BASELINE_ARGUMENTS = False

    class QBDIAnalysis:
        IMAGE_TAG = "qbdi_args_fuzzing"
        HOST_FOLDER = "/tmp/qbdi/"
        HOST_DICTIONARIES_FOLDER = HOST_FOLDER + "dictionaries/"
        HOST_EXECUTABLE_FOLDER = HOST_FOLDER + "target/"
        HOST_EXECUTABLE = HOST_EXECUTABLE_FOLDER + "target"
        HOST_RESULTS_FOLDER = HOST_FOLDER + "results/"
        CONTAINER_SO_FOLDER = "/home/docker"
        CONTAINER_EXECUTABLE_FOLDER = "/home/docker/target/"
        CONTAINER_EXECUTABLE = CONTAINER_EXECUTABLE_FOLDER + "target"
        CONTAINER_RESULTS_FOLDER = "/home/docker/results/"
        CONTAINER_TEMP_FILE = "/tmp/canary.opencrs"
