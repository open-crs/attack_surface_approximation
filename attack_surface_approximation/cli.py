import typing

import click
from rich import print  # pylint: disable=redefined-builtin
from rich.table import Table

from attack_surface_approximation.arguments_fuzzing import (ArgumentsFuzzer,
                                                            ArgumentsPair)
from attack_surface_approximation.dictionaries_generators import \
    ArgumentsGenerator
from attack_surface_approximation.static_input_streams_detection import (
    InputStreamsDetector, PresentInputStreams)


def read_dictionary(dictionary_name: str) -> typing.List[str]:
    with open(dictionary_name, "r", encoding="utf-8") as dictionary:
        arguments = dictionary.read().strip()
        arguments = arguments.split("\n")

        return arguments


def print_no_detected_stream() -> None:
    print(":x: No input mechanism was detected for the given program.")


def build_detected_streams_table(streams: dict) -> Table:
    table = Table()

    table.add_column("Stream")
    table.add_column("Present", justify="center")

    for key, value in streams.__dict__.items():
        is_present = "Yes" if value else "No"
        table.add_row(key, is_present)

    return table


def print_multiple_detected_streams(streams: dict) -> None:
    print(
        ":white_check_mark: Several input mechanisms were detected for the"
        " given program:\n"
    )

    table = build_detected_streams_table(streams)
    print(table)


def print_detected_streams(streams: PresentInputStreams) -> None:
    if not any(streams.__dict__.values()):
        print_no_detected_stream()
    else:
        print_multiple_detected_streams(streams)


def print_no_detected_argument() -> None:
    print(":x: No argument was detected for the given program.")


def build_arguments_table(arguments: typing.List[ArgumentsPair]) -> Table:
    table = Table()
    table.add_column("Argument")
    table.add_column("Role", justify="center")

    for argument in arguments:
        argument_str = argument.to_str()

        roles_str = [str(role) for role in argument.valid_roles]
        roles = ", ".join(roles_str)

        table.add_row(argument_str, roles)

    return table


def print_multiple_detected_arguments(
    arguments: typing.List[ArgumentsPair],
) -> None:
    print(
        ":white_check_mark: Several arguments were detected for the given"
        " program:\n"
    )

    table = build_arguments_table(arguments)
    print(table)


def print_arguments(arguments: typing.List[ArgumentsPair]) -> None:
    if not arguments:
        print_no_detected_argument()
    else:
        print_multiple_detected_arguments(arguments)


@click.group()
def cli() -> None:
    pass


@cli.command(help="Generate dictionaries with arguments, based on heuristics")
@click.option(
    "--heuristic",
    type=click.Choice(
        ArgumentsGenerator.get_available_heuristics(),
        case_sensitive=False,
    ),
    required=True,
    help="Generation heuristic",
)
@click.option(
    "--output",
    type=click.Path(exists=False, writable=True),
    required=True,
    help="Output filename",
)
@click.option(
    "--top",
    type=int,
    required=False,
    default=0,
    help=(
        "Number indicating how much arguments are returned after sorting by"
        " frequency"
    ),
)
def generate(heuristic: str, output: str, top: int) -> None:
    generator = ArgumentsGenerator()
    generator.generate(heuristic)
    generator.dump(output, top_count=top)


@cli.command(
    help="Statically detect what input streams are used by an executable"
)
@click.option(
    "--elf",
    type=click.Path(exists=True, readable=True),
    required=True,
    help="ELF Executable",
)
def detect(elf: str) -> None:
    detector = InputStreamsDetector(elf)
    streams = detector.detect_all()

    print_detected_streams(streams)


@cli.command(help="Fuzz the arguments of an executable")
@click.option(
    "--elf",
    type=click.Path(exists=True, readable=True),
    required=True,
    help="ELF Executable",
)
@click.option(
    "--dictionary",
    type=click.Path(exists=True, readable=True),
    required=True,
    help="Arguments dictionary",
)
def fuzz(elf: str, dictionary: str) -> None:
    dictionary_elements = read_dictionary(dictionary)

    fuzzer = ArgumentsFuzzer(elf, dictionary_elements)
    arguments = fuzzer.get_all_valid_arguments()

    print_arguments(arguments)


@cli.command(help="Analyze with all methods")
@click.option(
    "--elf",
    type=click.Path(exists=True, readable=True),
    required=True,
    help="ELF Executable",
)
@click.option(
    "--dictionary",
    type=click.Path(exists=True, readable=True),
    required=True,
    help="Arguments dictionary",
)
@click.pass_context
def analyze(ctx: click.Context, elf: str, dictionary: str) -> None:
    ctx.invoke(detect, elf=elf)
    print("")
    ctx.invoke(fuzz, elf=elf, dictionary=dictionary)


cli.add_command(generate)
cli.add_command(detect)
cli.add_command(fuzz)

if __name__ == "__main__":
    cli()
