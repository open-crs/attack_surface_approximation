"""Python script for generating arguments dictionaries.

This needs to be called only through Poetry, with the command specified in
README.md.
"""

import importlib
import pkgutil
import typing
from collections import Counter

import attack_surface_approximation.dictionaries_generators.heuristics


class TopFilter:
    def __init__(self, top, /):
        self.top = top

    def filter(self, elements: typing.List[str]):
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

    def dump(self, output_file, top_count: int = 0):
        # If required, prepare and use the filter
        if top_count != 0:
            top_filter = TopFilter(top_count)
            filter_func = getattr(top_filter, "filter", None)
            filtered_args = filter_func(self.arguments)
        else:
            filtered_args = self.arguments

        # Sort the arguments alphabetically
        arguments = list(filtered_args)
        arguments.sort()

        # Add a new line to each argument
        arguments = [argument + "\n" for argument in arguments]

        # Dump the arguments
        open(output_file, "w", encoding="utf-8").writelines(arguments)

    def generate(self, heuristic_id):
        heuristic_module = importlib.import_module(
            f"attack_surface_approximation.dictionaries_generators.heuristics.{heuristic_id}"
        )
        self.arguments = heuristic_module.generate()
