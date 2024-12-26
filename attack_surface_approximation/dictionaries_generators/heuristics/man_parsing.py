import gzip
import re
import typing

from commons.arguments import ARGUMENTS_PATTERN
from commons.manuals import get_all_manuals


def __unescape_bash_string(string: str) -> None:
    return string.replace(r"\-", "-")


def __find_arguments(string: str) -> typing.Generator[str, None, None]:
    arguments = re.findall(ARGUMENTS_PATTERN, string)

    yield from (argument.lstrip() for argument in arguments)


def __get_arguments_from_manual(
    filename: str,
    filter_func: typing.Callable,
    unescape: typing.Callable = None,
) -> typing.Generator[str, None, None]:
    try:
        manual = gzip.open(filename, "rt")
    except:
        return

    try:
        content = manual.read()
    except UnicodeDecodeError:
        return

    if unescape:
        content = unescape(content)

    arguments = filter_func(content)
    yield from arguments


def generate(_: str = None) -> typing.List[str]:
    all_arguments = set()
    for manual_filename in get_all_manuals():
        arguments = __get_arguments_from_manual(
            manual_filename, __find_arguments, unescape=__unescape_bash_string
        )
        all_arguments.update(arguments)

    return all_arguments

    return all_arguments
