import string
import typing


def generate() -> typing.Generator[str, None, None]:
    dictionary = string.ascii_letters + string.digits

    for char in dictionary:
        yield f"-{char}"
