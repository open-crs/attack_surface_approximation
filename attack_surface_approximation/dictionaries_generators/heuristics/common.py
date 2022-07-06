"""Module for generating arguments in the "-<letter>" format."""
import string


def generate():
    dictionary = string.ascii_letters + string.digits

    for char in dictionary:
        yield f"-{char}"
