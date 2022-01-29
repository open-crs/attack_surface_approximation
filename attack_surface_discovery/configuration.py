class Configuration:

    class AttackSurfaceDiscovery:
        # Folders
        GHIDRA_FOLDER = "/opt/ghidra/"
        GHIDRA_HEADLESS_ANALYZER = GHIDRA_FOLDER + "support/analyzeHeadless"
        GHIDRA_PROJECT_FOLDER = "/tmp/ghidra_projects/"

        # Relevant function calls
        # At the moment, some libcalls and syscalls (for example, vfscanf) are
        # omitted due to an assumption that they are not frequently used in
        # practice. This list will anyway be continuously update
        INPUT_INDICATOR_ENV = ["getenv"]
        INPUT_INDICATOR_NETWORKING = ["recv", "recvfrom", "recvmsg"]
        INPUT_INDICATOR_FILES_STDIN = [
            "read", "pread", "fread", "fgets", "fgetc", "fscanf"
        ]
        INPUT_INDICATOR_STDIN = [
            "getc", "getchar", "gets", "scanf", "__isoc99_scanf"
        ]

        # Miscellaneous
        GHIDRA_PROJECT_NAME = "project"
        GHIDRA_COMMAND_FMT = GHIDRA_HEADLESS_ANALYZER + " " + \
            GHIDRA_PROJECT_FOLDER + " " + GHIDRA_PROJECT_NAME + \
            " -import {} -overwrite -postscript {}"