class AttackSurfaceApproximationException(Exception):
    """Generic exception"""
    pass

class ELFNotFoundException(AttackSurfaceApproximationException):
    """The provided ELF file was not found."""
    pass

class NotELFFileException(AttackSurfaceApproximationException):
    """The provided file is not an ELF one."""
    pass

class MainNotFoundException(AttackSurfaceApproximationException):
    """The main function could not be found. Check if the binary is stripped."""
    pass