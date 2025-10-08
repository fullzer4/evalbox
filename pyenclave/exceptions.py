"""
Exceções específicas da biblioteca.
"""


class PreflightError(Exception):
    pass


class PolicyError(Exception):
    pass


class MountError(Exception):
    pass


class TimeoutError(Exception):
    pass


class ResourceLimitError(Exception):
    pass
