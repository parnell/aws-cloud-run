from __future__ import annotations

import json
from typing import Optional

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


def ensure_role(role_name: str, region_name: Optional[str] = None) -> str:
    """Ensure an IAM role for Lambda exists; return its ARN.

    The role gets the AWSLambdaBasicExecutionRole policy attached for logs.
    """

    iam = boto3.client("iam", region_name=region_name)

    try:
        role = iam.get_role(RoleName=role_name)["Role"]
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


def ensure_lambda(
    *,
    function_name: str,
    role_arn: str,
    zip_bytes: bytes,
    region_name: Optional[str] = None,
    runtime: str = "python3.12",
    timeout: int = 900,
    memory_size: int = 512,
    ephemeral_storage_mb: int = 512,
    architecture: str = "x86_64",
) -> str:
    """Ensure a Lambda function exists with the provided code; return its ARN."""

    lambda_client = boto3.client("lambda", region_name=region_name)

    try:
        get_resp = lambda_client.get_function(FunctionName=function_name)
        exists = True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            exists = False
        else:
            raise

    if exists:
        lambda_client.update_function_code(FunctionName=function_name, ZipFile=zip_bytes)
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Role=role_arn,
            Handler="handler.lambda_handler",
            Runtime=runtime,
            Timeout=timeout,
            MemorySize=memory_size,
            EphemeralStorage={"Size": ephemeral_storage_mb},
            Architectures=[architecture],
        )
        arn = get_resp["Configuration"]["FunctionArn"]
        return arn

    # Create
    create_resp = lambda_client.create_function(
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
    return create_resp["FunctionArn"]


