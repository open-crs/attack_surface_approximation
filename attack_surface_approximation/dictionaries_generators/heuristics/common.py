import string
import typing


def generate() -> typing.List[str]:
    dictionary = string.ascii_letters + string.digits

    return [f"-{char}" for char in dictionary]
