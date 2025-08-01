class MissingEnvironmentVariable(Exception):
    pass


class PomXmlValidationError(Exception):
    """Raised when validation or processing of the pom.xml fails."""

    def __init__(self, message: str):
        super().__init__(message)


class ExtractionError(Exception):
    """Raised when extracting an archive fails."""

    def __init__(self, message: str):
        super().__init__(message)


class DecompilationError(Exception):
    """Raised when decompiling a .jar archive fails."""

    def __init__(self, message: str):
        super().__init__(message)
