class InputStreamsDetectorException(Exception):
    """Generic exception"""


class ELFNotFoundException(InputStreamsDetectorException):
    """The provided ELF file was not found."""


class NotELFFileException(InputStreamsDetectorException):
    """The provided file is not an ELF one."""


class MainNotFoundException(InputStreamsDetectorException):
    """The main function could not be found. Check if the binary is stripped.
    """
