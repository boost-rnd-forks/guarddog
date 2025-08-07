class MissingEnvironmentVariable(Exception):
    pass


class PomXmlValidationError(Exception):
    """Raised when validation or processing of the pom.xml fails."""

    def __init__(self, message: str):
        super().__init__(message)


class DependencyGenerationError(Exception):
    """Raised when failure in generating dependencies."""

    def __init__(self, message: str):
        super().__init__(message)
