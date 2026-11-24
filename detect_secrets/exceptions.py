class UnableToReadBaselineError(ValueError):
    """Think of this as a 404, if getting a baseline had a HTTPError code."""
    pass


class InvalidBaselineError(ValueError):
    """Think of this as a 400, if getting a baseline had a HTTPError code."""
    pass


class IncompleteBaselineError(InvalidBaselineError):
    """
    Raised when a slim (incomplete) baseline is used in a context that requires a
    complete baseline. Slim baselines only describe a slice of the scanned results,
    so silently treating them as full baselines would drop previously recorded
    exclusions (e.g. secrets labelled as false positives).
    """
    def __init__(self, filename: str = '') -> None:
        location = f' ({filename})' if filename else ''
        super().__init__(
            'Refusing to use a slim baseline as a complete baseline{}: slim baselines '
            'only contain a slice of the scanned results and are missing exclusion '
            'records. Recreate a full baseline (without `--slim`) and try again.'.format(
                location,
            ),
        )


class InvalidFile(ValueError):
    """Think of this as a 400, if FileNotFoundError was a 404 HTTPError code."""
    pass


class SecretNotFoundOnSpecifiedLineError(Exception):
    def __init__(self, line: int) -> None:
        super().__init__(
            'ERROR: Secret not found on line {}!\n'.format(line)
            + 'Try recreating your baseline to fix this issue.',
        )


class NoLineNumberError(Exception):
    def __init__(self) -> None:
        super().__init__(
            'ERROR: No line numbers found in baseline! Line numbers are needed '
            'for auditing secret occurrences. Try recreating your baseline to fix '
            'this issue.',
        )
