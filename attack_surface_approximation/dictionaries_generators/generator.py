import importlib
import pkgutil
import typing
from collections import Counter

import attack_surface_approximation.dictionaries_generators.heuristics


class TopFilter:
    def __init__(self, top: int, /) -> None:
        self.top = top

    def filter(self, elements: typing.List[str]) -> typing.List[str]:
        counter = Counter(elements)

        return [element for element, _ in counter.most_common(self.top)]


class ArgumentsGenerator:
    arguments: typing.List[str]

    def __init__(self) -> None:
        self.arguments = []

    @staticmethod
    def get_available_heuristics() -> typing.Generator[str, None, None]:
        for _, name, _ in pkgutil.iter_modules(
            attack_surface_approximation.dictionaries_generators.heuristics.__path__
        ):
            yield name

    def load(self, dictionary_name: str) -> None:
        with open(dictionary_name, "r", encoding="utf-8") as dictionary:
            self.arguments = dictionary.read().strip()
            self.arguments = self.arguments.split("\n")

    def get_arguments(self) -> typing.List[str]:
        return self.arguments

    def dump(self, output_file: str, top_count: int = 0) -> int:
        if top_count != 0:
            top_filter = TopFilter(top_count)
            filter_func = getattr(top_filter, "filter", None)
            filtered_args = filter_func(self.arguments)
        else:
            filtered_args = self.arguments

        arguments = list(filtered_args)
        arguments.sort()

        arguments = [argument + "\n" for argument in arguments]

        open(output_file, "w", encoding="utf-8").writelines(arguments)

        return len(arguments)

    def generate(self, heuristic_id: str, elf: str) -> None:
        heuristic_module = importlib.import_module(
            "attack_surface_approximation.dictionaries_generators"
            f".heuristics.{heuristic_id}"
        )

        self.arguments = heuristic_module.generate(elf)
