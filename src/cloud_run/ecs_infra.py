"""ECS Fargate infrastructure for running long-running tasks."""

from __future__ import annotations

import json
import time
from typing import Optional

import boto3
from botocore.exceptions import ClientError


# IAM policy for ECS task execution (pulling images, writing logs)
ECS_TASK_EXECUTION_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup",
            ],
            "Resource": "*",
        }
    ],
}

ECS_TASK_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def ensure_ecs_execution_role(
    role_name: str = "cloud-run-ecs-execution-role",
    region_name: Optional[str] = None,
) -> str:
    """Ensure ECS task execution role exists; return its ARN."""
    iam = boto3.client("iam", region_name=region_name)

    try:
        role = iam.get_role(RoleName=role_name)["Role"]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
        # Create role
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(ECS_TASK_ASSUME_ROLE_POLICY),
            Description="Execution role for cloud-run ECS tasks",
        )["Role"]

    # Attach AWS managed policy for ECS task execution
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError:
        pass  # Already attached or doesn't exist in test env

    return role["Arn"]


def ensure_ecs_cluster(
    cluster_name: str = "cloud-run-cluster",
    region_name: Optional[str] = None,
) -> str:
    """Ensure ECS cluster exists; return its ARN."""
    ecs = boto3.client("ecs", region_name=region_name)

    try:
        response = ecs.describe_clusters(clusters=[cluster_name])
        clusters = response.get("clusters", [])
        active_clusters = [c for c in clusters if c["status"] == "ACTIVE"]
        if active_clusters:
            return active_clusters[0]["clusterArn"]
    except ClientError:
        pass

    # Create cluster
    response = ecs.create_cluster(
        clusterName=cluster_name,
        capacityProviders=["FARGATE", "FARGATE_SPOT"],
        defaultCapacityProviderStrategy=[
            {"capacityProvider": "FARGATE", "weight": 1},
        ],
    )
    return response["cluster"]["clusterArn"]


def get_vpc_subnets(
    region_name: Optional[str] = None,
    vpc_id: Optional[str] = None,
    subnet_ids: Optional[list[str]] = None,
) -> tuple[str, list[str]]:
    """Get VPC ID and subnet IDs for running Fargate tasks.

    If vpc_id and subnet_ids are provided, validates and returns them.
    Otherwise, tries to find a suitable VPC (default first, then any VPC).
    """
    ec2 = boto3.client("ec2", region_name=region_name)

    # If specific subnets provided, use them
    if subnet_ids:
        if not vpc_id:
            # Get VPC from first subnet
            subnets = ec2.describe_subnets(SubnetIds=subnet_ids[:1])
            if subnets["Subnets"]:
                vpc_id = subnets["Subnets"][0]["VpcId"]
            else:
                raise RuntimeError(f"Subnet {subnet_ids[0]} not found")
        assert vpc_id is not None  # For type checker
        return vpc_id, subnet_ids

    # If specific VPC provided, get its subnets
    if vpc_id:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        found_subnet_ids = [s["SubnetId"] for s in subnets["Subnets"]]
        if not found_subnet_ids:
            raise RuntimeError(f"No subnets found in VPC {vpc_id}")
        return vpc_id, found_subnet_ids

    # Try to find default VPC first
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])
    if vpcs["Vpcs"]:
        found_vpc_id: str = vpcs["Vpcs"][0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [found_vpc_id]}])
        found_subnet_ids = [s["SubnetId"] for s in subnets["Subnets"]]
        if found_subnet_ids:
            return found_vpc_id, found_subnet_ids

    # No default VPC, try to find any VPC with public subnets
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs.get("Vpcs", []):
        found_vpc_id = vpc["VpcId"]
        # Look for subnets that can assign public IPs (needed for Fargate to pull images)
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [found_vpc_id]},
                {"Name": "map-public-ip-on-launch", "Values": ["true"]},
            ]
        )
        found_subnet_ids = [s["SubnetId"] for s in subnets["Subnets"]]
        if found_subnet_ids:
            return found_vpc_id, found_subnet_ids

        # Try any subnet in this VPC
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [found_vpc_id]}])
        found_subnet_ids = [s["SubnetId"] for s in subnets["Subnets"]]
        if found_subnet_ids:
            return found_vpc_id, found_subnet_ids

    raise RuntimeError(
        "No suitable VPC/subnets found. Either:\n"
        "  1. Create a default VPC: aws ec2 create-default-vpc --region us-east-2\n"
        "  2. Specify VPC/subnets: --vpc vpc-xxx --subnets subnet-xxx,subnet-yyy"
    )


# Keep old name for compatibility
def get_default_vpc_subnets(region_name: Optional[str] = None) -> tuple[str, list[str]]:
    """Get default VPC ID and its subnet IDs. Deprecated: use get_vpc_subnets instead."""
    return get_vpc_subnets(region_name=region_name)


def ensure_log_group(
    log_group_name: str,
    region_name: Optional[str] = None,
) -> None:
    """Ensure CloudWatch log group exists."""
    logs = boto3.client("logs", region_name=region_name)

    try:
        logs.create_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            raise


def register_task_definition(
    family: str,
    execution_role_arn: str,
    script_type: str,
    cpu: str = "256",
    memory: str = "512",
    region_name: Optional[str] = None,
) -> str:
    """Register an ECS task definition for running scripts.

    The task definition uses a minimal command that will be overridden at runtime.
    The actual script is passed via command override when running the task.
    """
    ecs = boto3.client("ecs", region_name=region_name)

    log_group = f"/ecs/{family}"
    ensure_log_group(log_group, region_name=region_name)

    # Use Amazon ECR Public images (works without internet via PrivateLink)
    # These are more reliable than Docker Hub in AWS environments
    if script_type == "python":
        image = "public.ecr.aws/docker/library/python:3.12-slim"
    else:
        image = "public.ecr.aws/amazonlinux/amazonlinux:2023"

    # Get region for log configuration
    if region_name is None:
        session = boto3.Session()
        region_name = session.region_name

    response = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu=cpu,
        memory=memory,
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": "script-runner",
                "image": image,
                "essential": True,
                # Default command - will be overridden at runtime
                "command": ["echo", "No script provided"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": region_name,
                        "awslogs-stream-prefix": "task",
                    },
                },
            }
        ],
    )
    return response["taskDefinition"]["taskDefinitionArn"]


def _strip_shell_comments(script: str) -> str:
    """Strip comment-only lines and blank lines from shell scripts to reduce size."""
    lines = []
    for line in script.split("\n"):
        # Keep shebang
        if line.startswith("#!"):
            lines.append(line)
            continue

        # Skip blank lines and comment-only lines
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            continue

        lines.append(line)

    return "\n".join(lines)


def run_ecs_task(
    cluster_arn: str,
    task_definition_arn: str,
    subnet_ids: list[str],
    script_content: str,
    script_type: str = "python",
    script_args: Optional[list[str]] = None,
    env_vars: Optional[dict[str, str]] = None,
    secrets: Optional[list[str]] = None,
    runtime_secrets: Optional[list[str]] = None,
    container_name: str = "script-runner",
    security_group_ids: Optional[list[str]] = None,
    region_name: Optional[str] = None,
) -> str:
    """Run an ECS Fargate task; return task ARN.

    The script is stripped of comments, gzip compressed, and base64-encoded.
    For very large scripts (>5KB compressed), uploads to S3 and uses boto3 to fetch.

    Note: ECS API only allows overriding 'command', not 'entryPoint'.
    - If the image has no ENTRYPOINT: our command runs directly ✓
    - If the image has ENTRYPOINT with 'exec "$@"' pattern: our command runs after setup ✓
    - If the image has a fixed ENTRYPOINT: may conflict (use a different task definition)
    """
    import base64
    import gzip
    import json
    import sys

    ecs = boto3.client("ecs", region_name=region_name)

    # Strip comments for shell scripts to reduce size
    if script_type == "shell":
        original_size = len(script_content)
        script_content = _strip_shell_comments(script_content)
        stripped_size = len(script_content)
        if stripped_size < original_size:
            print(
                f"[cloud_run] Script stripped: {original_size} → {stripped_size} bytes ({100 - stripped_size * 100 // original_size}% reduction)",
                file=sys.stderr,
            )

    # Gzip compress then base64 encode the script
    compressed = gzip.compress(script_content.encode())
    script_b64 = base64.b64encode(compressed).decode()

    # Prepare args
    args_list = script_args or []
    args_json = json.dumps(args_list)

    # Show script size info
    print(f"[cloud_run] Script size after compression: {len(script_b64)} bytes", file=sys.stderr)

    # Build secret-fetching code if runtime_secrets specified
    # This fetches secrets inside the container using boto3, avoiding the 8KB override limit
    secrets_loader = ""
    if runtime_secrets:
        secrets_json = json.dumps(runtime_secrets)
        # Compact single-line Python using list comprehension and exec
        # Fetches each secret, parses JSON, exports all keys as env vars
        secrets_loader = f"import boto3,os;_sm=boto3.client('secretsmanager');[os.environ.update({{str(k):str(v) for k,v in json.loads(_sm.get_secret_value(SecretId=s).get('SecretString','{{}}')).items()}}) for s in {secrets_json}];"

    # Build command that decompresses and executes the script inline
    if script_type == "python":
        command = [
            "python",
            "-c",
            f"import base64,gzip,sys,json;{secrets_loader}sys.argv=['script']+json.loads('{args_json}');exec(gzip.decompress(base64.b64decode('{script_b64}')).decode())",
        ]
    else:
        # For bash: use Python subprocess to run bash with the script
        # This avoids writing to disk (read-only filesystem) and handles args properly
        command = [
            "python3",
            "-c",
            f"import base64,gzip,subprocess,sys,json;{secrets_loader}script=gzip.decompress(base64.b64decode('{script_b64}')).decode();args=json.loads('{args_json}');sys.exit(subprocess.call(['/bin/bash','-c',script,'bash']+args))",
        ]

    # Build network configuration
    network_config = {
        "subnets": subnet_ids[:3],  # Use up to 3 subnets
        "assignPublicIp": "ENABLED",  # Needed to pull images if no NAT
    }
    if security_group_ids:
        network_config["securityGroups"] = security_group_ids

    # Build container override
    container_override: dict = {
        "name": container_name,
        "command": command,
    }

    # Fetch secrets from Secrets Manager and merge into env vars
    all_env_vars = dict(env_vars) if env_vars else {}
    if secrets:
        sm = boto3.client("secretsmanager", region_name=region_name)
        for secret_name in secrets:
            try:
                resp = sm.get_secret_value(SecretId=secret_name)
                secret_value = resp.get("SecretString")
                if secret_value:
                    secret_dict = json.loads(secret_value)
                    if isinstance(secret_dict, dict):
                        count = len(secret_dict)
                        all_env_vars.update({str(k): str(v) for k, v in secret_dict.items()})
                        print(f"[cloud_run] Loaded {count} environment variables from '{secret_name}'", file=sys.stderr)
                    else:
                        print(f"[cloud_run] Warning: Secret '{secret_name}' is not a JSON object, skipping", file=sys.stderr)
            except Exception as e:
                raise RuntimeError(f"Failed to fetch secret '{secret_name}': {e}")

    # Add environment variables if provided
    if all_env_vars:
        container_override["environment"] = [{"name": k, "value": v} for k, v in all_env_vars.items()]

    # Check container overrides size before calling API
    overrides = {"containerOverrides": [container_override]}
    overrides_json = json.dumps(overrides)
    overrides_size = len(overrides_json)
    
    ECS_OVERRIDES_LIMIT = 8192
    if overrides_size > ECS_OVERRIDES_LIMIT:
        # Calculate breakdown for helpful error message
        command_size = len(json.dumps(container_override.get("command", [])))
        env_size = len(json.dumps(container_override.get("environment", [])))
        env_count = len(all_env_vars) if all_env_vars else 0
        
        error_msg = (
            f"Container overrides exceed ECS limit of {ECS_OVERRIDES_LIMIT} bytes.\n"
            f"  Total size: {overrides_size} bytes (limit: {ECS_OVERRIDES_LIMIT})\n"
            f"  - Command (script + args): {command_size} bytes\n"
            f"  - Environment variables ({env_count}): {env_size} bytes\n"
        )
        
        if env_size > command_size:
            error_msg += (
                "\nThe environment variables are the main contributor. Consider:\n"
                "  1. Using fewer secrets or smaller secret values\n"
                "  2. Configuring secrets in the task definition instead of runtime overrides\n"
                "  3. Using AWS Secrets Manager references in the task definition"
            )
        else:
            error_msg += (
                "\nThe script is the main contributor. Consider:\n"
                "  1. Reducing script size\n"
                "  2. Moving logic to a pre-built container image"
            )
        
        raise RuntimeError(error_msg)

    response = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_definition_arn,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": network_config},
        overrides={"containerOverrides": [container_override]},
    )

    if not response.get("tasks"):
        failures = response.get("failures", [])
        raise RuntimeError(f"Failed to start ECS task: {failures}")

    return response["tasks"][0]["taskArn"]


def wait_for_task_completion(
    cluster_arn: str,
    task_arn: str,
    region_name: Optional[str] = None,
    poll_interval: int = 5,
    timeout: int = 3600,
    log_group: Optional[str] = None,
    container_name: Optional[str] = None,
) -> dict:
    """Wait for ECS task to complete; return task info.

    If log_group and container_name are provided, streams logs in real-time.
    """
    import sys

    ecs = boto3.client("ecs", region_name=region_name)
    logs_client = boto3.client("logs", region_name=region_name) if log_group else None

    start_time = time.time()
    last_status = None
    task_id = task_arn.split("/")[-1]

    # For log streaming
    next_token = None
    log_stream_name = None
    logs_started = False

    while time.time() - start_time < timeout:
        response = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])

        if not response.get("tasks"):
            raise RuntimeError(f"Task {task_arn} not found")

        task = response["tasks"][0]
        status = task.get("lastStatus", "UNKNOWN")

        # Print status changes
        if status != last_status:
            elapsed = int(time.time() - start_time)
            print(f"[cloud_run] Task status: {status} ({elapsed}s)", file=sys.stderr)
            last_status = status

        # Stream logs while RUNNING
        if status == "RUNNING" and log_group and container_name and logs_client:
            # Find the log stream if we haven't yet
            if not log_stream_name:
                log_stream_name = _find_log_stream(logs_client, log_group, task_id, container_name)
                if log_stream_name and not logs_started:
                    print("[cloud_run] --- Live logs ---", file=sys.stderr)
                    logs_started = True

            # Fetch new log events
            if log_stream_name:
                next_token = _stream_new_logs(logs_client, log_group, log_stream_name, next_token)

        if status == "STOPPED":
            # Fetch any remaining logs
            if log_stream_name and logs_client and log_group:
                _stream_new_logs(logs_client, log_group, log_stream_name, next_token)
                if logs_started:
                    print("[cloud_run] --- End logs ---", file=sys.stderr)
            return task

        time.sleep(poll_interval)

    raise RuntimeError(f"Task {task_arn} did not complete within {timeout} seconds")


def _find_log_stream(
    logs_client, log_group: str, task_id: str, container_name: str
) -> Optional[str]:
    """Find the log stream for a task."""
    # Try common patterns
    patterns = [
        f"task/{container_name}/{task_id}",
        f"ecs/{container_name}/{task_id}",
        f"{container_name}/{container_name}/{task_id}",
        f"{container_name}/{task_id}",
    ]

    for pattern in patterns:
        try:
            logs_client.describe_log_streams(
                logGroupName=log_group,
                logStreamNamePrefix=pattern[: pattern.rfind("/") + 1]
                if "/" in pattern
                else pattern,
                limit=1,
            )
            # Check if exact stream exists
            try:
                logs_client.get_log_events(
                    logGroupName=log_group,
                    logStreamName=pattern,
                    limit=1,
                )
                return pattern
            except ClientError:
                continue
        except ClientError:
            continue

    # Search for any stream with the task ID
    try:
        streams = logs_client.describe_log_streams(
            logGroupName=log_group,
            orderBy="LastEventTime",
            descending=True,
            limit=20,
        )
        for stream in streams.get("logStreams", []):
            if task_id in stream.get("logStreamName", ""):
                return stream["logStreamName"]
    except ClientError:
        pass

    return None


def _stream_new_logs(
    logs_client, log_group: str, log_stream: str, next_token: Optional[str]
) -> Optional[str]:
    """Fetch and print new log events, return next token."""
    try:
        kwargs = {
            "logGroupName": log_group,
            "logStreamName": log_stream,
            "startFromHead": True,
        }
        if next_token:
            kwargs["nextToken"] = next_token

        response = logs_client.get_log_events(**kwargs)

        for event in response.get("events", []):
            print(event.get("message", ""))

        # Return the next token for pagination
        new_token = response.get("nextForwardToken")
        # CloudWatch returns the same token if no new events
        if new_token != next_token:
            return new_token
        return next_token

    except ClientError:
        return next_token


def get_task_logs(
    log_group: str,
    task_id: str,
    container_name: str = "script-runner",
    region_name: Optional[str] = None,
) -> str:
    """Fetch CloudWatch logs for an ECS task."""
    logs_client = boto3.client("logs", region_name=region_name)

    # Try multiple stream name formats (different awslogs-stream-prefix values)
    possible_streams = [
        f"task/{container_name}/{task_id}",  # prefix: task
        f"ecs/{container_name}/{task_id}",  # prefix: ecs
        f"{container_name}/{container_name}/{task_id}",  # prefix: container_name
        f"{container_name}/{task_id}",  # some configs
    ]

    for log_stream in possible_streams:
        try:
            response = logs_client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream,
                startFromHead=True,
            )

            events = response.get("events", [])
            if events:
                return "\n".join(event["message"] for event in events)
        except ClientError:
            continue

    # None of the expected formats worked, search for the task ID
    return _try_find_logs(logs_client, log_group, task_id, container_name)


def _try_find_logs(logs_client, log_group: str, task_id: str, container_name: str) -> str:
    """Try to find and fetch logs from any matching stream."""
    try:
        # Try different prefixes when searching
        prefixes_to_try = ["task/", "ecs/", f"{container_name}/"]

        for prefix in prefixes_to_try:
            try:
                streams = logs_client.describe_log_streams(
                    logGroupName=log_group,
                    logStreamNamePrefix=prefix,
                    orderBy="LastEventTime",
                    descending=True,
                    limit=20,
                )

                # Look for a stream containing the task ID
                for stream in streams.get("logStreams", []):
                    stream_name = stream.get("logStreamName", "")
                    if task_id in stream_name:
                        response = logs_client.get_log_events(
                            logGroupName=log_group,
                            logStreamName=stream_name,
                            startFromHead=True,
                        )
                        events = response.get("events", [])
                        if events:
                            return "\n".join(event["message"] for event in events)
            except ClientError:
                continue

        # Try listing all streams without prefix filter
        try:
            streams = logs_client.describe_log_streams(
                logGroupName=log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=50,
            )

            # Look for a stream containing the task ID
            for stream in streams.get("logStreams", []):
                stream_name = stream.get("logStreamName", "")
                if task_id in stream_name:
                    response = logs_client.get_log_events(
                        logGroupName=log_group,
                        logStreamName=stream_name,
                        startFromHead=True,
                    )
                    events = response.get("events", [])
                    if events:
                        return "\n".join(event["message"] for event in events)

            available = [s.get("logStreamName", "") for s in streams.get("logStreams", [])]
            if available:
                return f"(No logs found for task {task_id}. Recent streams: {available[:3]})"
        except ClientError:
            pass

        return f"(No log streams found in {log_group})"

    except ClientError as e:
        return f"(Could not fetch logs: {e})"
