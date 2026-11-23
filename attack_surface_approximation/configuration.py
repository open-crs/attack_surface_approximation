import os

_TARGET_ARCH = os.environ.get("OPENCRS_TARGET_ARCH", "x86")

class Configuration:
    class Fuzzer:
        GENERATE_RANDOM_BASELINE_ARGUMENTS = False

    class Toolchain:
        TARGET_ARCH = os.environ.get("OPENCRS_TARGET_ARCH", "x86")
        _SUPPORTED_ARCHS = ("x86", "aarch64")

        if TARGET_ARCH not in _SUPPORTED_ARCHS:
            raise ValueError(
                "Unsupported OPENCRS_TARGET_ARCH="
                f"{TARGET_ARCH!r}; expected one of {_SUPPORTED_ARCHS}"
            )
    
    class QBDIAnalysis:
        _IMAGE_TAGS = {
            "x86": "qbdi_args_fuzzing",
            "aarch64": "qbdi_args_fuzzing_aarch64",
        }

        @classmethod
        def image_tag(cls):
            return cls._IMAGE_TAGS[Configuration.Toolchain.TARGET_ARCH]

        HOST_FOLDER = f"/tmp/qbdi/{_TARGET_ARCH}/"
        HOST_DICTIONARIES_FOLDER = HOST_FOLDER + "dictionaries/"
        HOST_EXECUTABLE_FOLDER = HOST_FOLDER + "target/"
        HOST_EXECUTABLE = HOST_EXECUTABLE_FOLDER + "target"
        HOST_RESULTS_FOLDER = HOST_FOLDER + "results/"
        CONTAINER_SO_FOLDER = "/home/docker"
        CONTAINER_EXECUTABLE_FOLDER = "/home/docker/target/"
        CONTAINER_EXECUTABLE = CONTAINER_EXECUTABLE_FOLDER + "target"
        CONTAINER_RESULTS_FOLDER = "/home/docker/results/"
        CONTAINER_TEMP_FILE = "/tmp/canary.opencrs"
