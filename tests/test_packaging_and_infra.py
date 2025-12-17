from __future__ import annotations

import boto3
import cloudpickle  # type: ignore
from moto import mock_aws

from cloud_run.aws_infra import ensure_lambda, ensure_role
from cloud_run.packaging import build_deployment_zip


@mock_aws
def test_build_zip_and_ensure_infra():
    # Build zip from a simple function
    def add(x, y):
        return x + y

    zip_bytes = build_deployment_zip(cloudpickle.dumps(add))
    assert isinstance(zip_bytes, bytes | bytearray)
    assert len(zip_bytes) > 1000

    # Ensure IAM role
    role_arn = ensure_role("pi-cloud-runner-role", region_name="us-east-1")
    assert role_arn.startswith("arn:aws:iam::")

    # Ensure Lambda function
    fn_arn = ensure_lambda(
        function_name="pi-cloud-run-test-add",
        role_arn=role_arn,
        zip_bytes=zip_bytes,
        region_name="us-east-1",
        runtime="python3.8",
    )
    assert fn_arn.startswith("arn:aws:lambda:")

    # Validate function exists and configuration looks correct
    client = boto3.client("lambda", region_name="us-east-1")
    fn = client.get_function(FunctionName="pi-cloud-run-test-add")
    assert fn["Configuration"]["Handler"] == "handler.lambda_handler"
    assert fn["Configuration"]["Runtime"] == "python3.8"
