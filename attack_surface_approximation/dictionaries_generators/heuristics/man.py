"""Module for extracting arguments from manual pages."""
import gzip
import os
import re


def __get_possible_man_locations():
    for conf_filename in ["/etc/manpath.config", "/etc/man_db.conf"]:
        if os.path.isfile(conf_filename):
            with open(conf_filename, "r", encoding="utf-8") as conf_file:
                content = conf_file.read().split("\n")

                # Mandatory paths
                mandatory_lines = [
                    line for line in content if line.startswith("MANDATORY_MANPATH")
                ]
                for line in mandatory_lines:
                    yield line.split()[-1]

                # Executables path maps
                path_maps = [line for line in content if line.startswith("MANPATH_MAP")]
                for line in path_maps:
                    yield line.split()[-1]


def __get_manuals_from_location(location, /):
    for dirpath, _, filenames in os.walk(location):
        for filename in filenames:
            if filename.endswith(".gz"):
                yield os.path.join(dirpath, filename)


def __get_all_manuals():
    man_locations_iter = __get_possible_man_locations()
    for location in man_locations_iter:
        yield from __get_manuals_from_location(location)


def __unescape_bash_string(string, /):
    return string.replace(r"\-", "-")


def __find_arguments(string, /):
    arguments = re.findall(r"\s-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*", string)

    yield from (argument.lstrip() for argument in arguments)


def __get_arguments_from_manual(filename, filter_func, /, *, unescape=None):
    with gzip.open(filename, "rt") as manual:
        try:
            content = manual.read()
        except UnicodeDecodeError:
            # If an exception is raised, then the file is in other language than
            # English.
            return

        if unescape:
            content = unescape(content)

        arguments = filter_func(content)
        yield from arguments


def generate():
    # Get the arguments and ensure their uniqueness
    all_arguments = set()
    for manual_filename in __get_all_manuals():
        arguments = __get_arguments_from_manual(
            manual_filename, __find_arguments, unescape=__unescape_bash_string
        )
        all_arguments.update(arguments)

    return all_arguments
