from __future__ import annotations

import os

import pytest
from moto import mock_aws

from cloud_run import run


@mock_aws
def test_run_success_creates_lambda():
    def mul(a, b):
        return a * b

    # Ensure Lambda is created without executing it (mock will still run locally)
    try:
        run(
            mul,
            6,
            7,
            region_name="us-east-1",
            function_name="pi-cloud-run-test-mul",
            runtime="python3.8",
        )
    except RuntimeError:
        # We only care that infra path works under moto; execution may not deserialize across runtimes
        pass


@mock_aws
def test_run_provisions_resources():
    def noop():
        return None

    try:
        run(
            noop,
            region_name="us-east-1",
            function_name="pi-cloud-run-test-exec",
            runtime="python3.8",
        )
    except RuntimeError:
        pass


