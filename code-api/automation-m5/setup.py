import sys

from setuptools import setup
from setuptools.command.test import test


def run_tests(*args):
    from sample_app.tests import run_tests
    errors = run_tests()
    if errors:
        sys.exit(1)
    else:
        sys.exit(0)


test.run_tests = run_tests


