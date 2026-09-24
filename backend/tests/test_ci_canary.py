import os


def test_ci_catches_lint_error() -> None:
    assert sum([1, 1]) == 2
