from __future__ import annotations

import json
import time

import boto3
from botocore.exceptions import ClientError

LAMBDA_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def ensure_role(role_name: str, region_name: str | None = None) -> str:
    """Ensure an IAM role for Lambda exists; return its ARN.

    The role gets the AWSLambdaBasicExecutionRole policy attached for logs.
    If the role exists but has an incorrect trust policy, it will be updated.
    """

    iam = boto3.client("iam", region_name=region_name)

    try:
        role = iam.get_role(RoleName=role_name)["Role"]
        # Check if trust policy allows Lambda service to assume the role
        # AssumeRolePolicyDocument can be a dict or a JSON string depending on boto3 version
        assume_policy_doc = role["AssumeRolePolicyDocument"]
        if isinstance(assume_policy_doc, str):
            current_policy = json.loads(assume_policy_doc)
        else:
            current_policy = assume_policy_doc

        # Check if the policy allows lambda.amazonaws.com to assume the role
        allows_lambda = False
        for statement in current_policy.get("Statement", []):
            principal = statement.get("Principal", {})
            if isinstance(principal, dict):
                service = principal.get("Service", "")
                if service == "lambda.amazonaws.com" and statement.get("Effect") == "Allow":
                    allows_lambda = True
                    break

        if not allows_lambda:
            # Update trust policy to allow Lambda to assume the role
            iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(LAMBDA_ASSUME_ROLE_POLICY),
            )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code != "NoSuchEntity":
            raise
        # Create role
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(LAMBDA_ASSUME_ROLE_POLICY),
            Description="Execution role for pi-cloud-run managed Lambdas",
        )["Role"]

    # Ensure basic execution policy is attached
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    if not any(p["PolicyArn"] == policy_arn for p in attached):
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as e:
            # In moto, AWS managed policies are not pre-provisioned. Fallback to an inline
            # policy that grants basic CloudWatch Logs permissions so Lambda can run.
            error_code = e.response.get("Error", {}).get("Code")
            if error_code != "NoSuchEntity":
                raise
            inline_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "*",
                    }
                ],
            }
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="pi-cloud-run-basic-logs",
                PolicyDocument=json.dumps(inline_policy),
            )

    return role["Arn"]


# Create and update both return only when the function is Active. Callers invoke.
_LAMBDA_READY_TIMEOUT_SECONDS = 60


def _poll_lambda_state(lambda_client, function_name: str, *, ready: frozenset[str]) -> str:
    """Poll GetFunction until state is in ready. Return the function ARN.

    Failed is an error. Any other state waits out the ready timeout.
    Active and Inactive are ready for a configuration change; only Active is
    ready to return to a caller that will invoke.
    """
    deadline = time.time() + _LAMBDA_READY_TIMEOUT_SECONDS
    while time.time() < deadline:
        try:
            configuration = lambda_client.get_function(FunctionName=function_name)["Configuration"]
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                time.sleep(1)
                continue
            raise
        state = configuration["State"]
        if state == "Failed":
            raise RuntimeError(f"Lambda function {function_name} is in Failed state")
        if state in ready:
            return configuration["FunctionArn"]
        time.sleep(1)
    raise RuntimeError(
        f"Lambda function {function_name} did not become Active within "
        f"{_LAMBDA_READY_TIMEOUT_SECONDS} seconds"
    )


def ensure_lambda(
    *,
    function_name: str,
    role_arn: str,
    zip_bytes: bytes,
    region_name: str | None = None,
    runtime: str = "python3.12",
    timeout: int = 900,
    memory_size: int = 512,
    ephemeral_storage_mb: int = 512,
    architecture: str = "x86_64",
) -> str:
    """Ensure a Lambda function exists and is Active; return its ARN."""

    lambda_client = boto3.client("lambda", region_name=region_name)

    try:
        lambda_client.get_function(FunctionName=function_name)
        exists = True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            exists = False
        else:
            raise

    if exists:
        lambda_client.update_function_code(FunctionName=function_name, ZipFile=zip_bytes)
        # Configuration updates are rejected while a code update is still pending.
        _poll_lambda_state(
            lambda_client,
            function_name,
            ready=frozenset({"Active", "Inactive"}),
        )

        max_config_retries = 10
        for attempt in range(max_config_retries):
            try:
                # Architectures cannot be changed after creation, so omit them here.
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Role=role_arn,
                    Handler="handler.lambda_handler",
                    Runtime=runtime,
                    Timeout=timeout,
                    MemorySize=memory_size,
                    EphemeralStorage={"Size": ephemeral_storage_mb},
                )
                break
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "ResourceConflictException" and attempt < max_config_retries - 1:
                    time.sleep(2)
                    continue
                raise
    else:
        lambda_client.create_function(
            FunctionName=function_name,
            Role=role_arn,
            Runtime=runtime,
            Handler="handler.lambda_handler",
            Code={"ZipFile": zip_bytes},
            Timeout=timeout,
            MemorySize=memory_size,
            EphemeralStorage={"Size": ephemeral_storage_mb},
            Architectures=[architecture],
            Publish=True,
        )

    return _poll_lambda_state(lambda_client, function_name, ready=frozenset({"Active"}))
