import gzip
import re
import typing

from commons.manuals import get_all_manuals


def __unescape_bash_string(string: str) -> None:
    return string.replace(r"\-", "-")


def __find_arguments(string: str) -> typing.Generator[str, None, None]:
    arguments = re.findall(r"\s-{1,2}[a-zA-Z0-9][a-zA-Z0-9_-]*", string)

    yield from (argument.lstrip() for argument in arguments)


def __get_arguments_from_manual(
    filename: str,
    filter_func: typing.Callable,
    unescape: typing.Callable = None,
) -> typing.Generator[str, None, None]:
    with gzip.open(filename, "rt") as manual:
        try:
            content = manual.read()
        except UnicodeDecodeError:
            return

        if unescape:
            content = unescape(content)

        arguments = filter_func(content)
        yield from arguments


def generate() -> typing.List[str]:
    all_arguments = set()
    for manual_filename in get_all_manuals():
        arguments = __get_arguments_from_manual(
            manual_filename, __find_arguments, unescape=__unescape_bash_string
        )
        all_arguments.update(arguments)

    return all_arguments
