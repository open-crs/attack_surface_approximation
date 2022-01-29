class InputDiscoveryException(Exception):
    """Generic exception"""
    pass

class ELFNotFoundException(InputDiscoveryException):
    """The provided ELF file was not found."""
    pass

class NotELFFileException(InputDiscoveryException):
    """The provided file is not an ELF one."""
    pass

class MainNotFoundException(InputDiscoveryException):
    """The main function could not be found. Check if the binary is stripped."""
    pass