import re
import typing

from commons.arguments import ARGUMENTS_PATTERN


def generate(elf: str = None) -> typing.List[str]:
    content = open(elf, "rb").read()

    arguments = re.findall(ARGUMENTS_PATTERN.encode("utf-8"), content)

    return [arg.decode("utf-8") for arg in arguments]
