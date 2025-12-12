"""CLI for running scripts on AWS Lambda or ECS Fargate."""

import argparse
import sys
from pathlib import Path

import boto3

from .lambda_runner import run_on_lambda
from .ecs_runner import (
    list_ecs_tasks,
    list_task_definitions,
    list_vpcs,
    run_on_ecs,
)


def _detect_script_type(script_path: Path, script_content: str) -> str:
    """Detect whether a script is Python or shell based on extension and shebang.

    Returns: 'python' or 'shell'
    """
    # Check file extension first
    ext = script_path.suffix.lower()
    if ext == ".py":
        return "python"
    elif ext in (".sh", ".bash"):
        return "shell"

    # Check shebang
    first_line = script_content.split("\n")[0].strip()
    if first_line.startswith("#!"):
        if "python" in first_line.lower():
            return "python"
        elif any(shell in first_line.lower() for shell in ["sh", "bash", "zsh", "fish"]):
            return "shell"

    # Default to shell for backward compatibility
    return "shell"


def main():
    parser = argparse.ArgumentParser(
        description="Run a shell script or Python script on AWS Lambda or ECS Fargate"
    )
    parser.add_argument(
        "script",
        nargs="?",
        help="Path to the script to run (Python .py or shell script)",
    )
    parser.add_argument(
        "script_args",
        nargs="*",
        help="Arguments to pass to the script (after -- separator)",
    )
    parser.add_argument(
        "-e", "--env-var",
        action="append",
        dest="env_vars",
        metavar="KEY=VALUE",
        help="Environment variable to set in the task. Can be specified multiple times.",
    )
    parser.add_argument(
        "--secret",
        action="append",
        dest="secrets",
        metavar="SECRET_NAME",
        help="Secrets Manager secret name/ARN. All key-value pairs from the secret JSON will be injected as env vars (passed via container overrides, counts toward 8KB limit).",
    )
    parser.add_argument(
        "--runtime-secret",
        action="append",
        dest="runtime_secrets",
        metavar="SECRET_NAME",
        help="Like --secret, but fetched inside the container at runtime (requires boto3 in container, avoids 8KB override limit).",
    )
    parser.add_argument("--function-name", help="Lambda function name (default: auto-generated)")
    parser.add_argument(
        "--region", default=None, help="AWS region (default: from AWS config/profile)"
    )
    parser.add_argument(
        "--ecs",
        action="store_true",
        help="Run on ECS Fargate instead of Lambda (for tasks > 15 minutes)",
    )
    parser.add_argument(
        "--cpu",
        default="256",
        help="ECS task CPU units (default: 256, options: 256, 512, 1024, 2048, 4096)",
    )
    parser.add_argument("--memory", default="512", help="ECS task memory in MB (default: 512)")
    parser.add_argument(
        "--task-definition",
        help="Use existing ECS task definition (ARN or family:revision)",
    )
    parser.add_argument("--cluster", help="ECS cluster name (required for --ecs)")
    parser.add_argument(
        "--create-cluster",
        action="store_true",
        help="Create ECS cluster if it doesn't exist",
    )
    parser.add_argument("--vpc", help="VPC name or ID for ECS tasks (optional, can be inferred)")
    parser.add_argument("--subnets", help="Comma-separated subnet IDs (optional, can be inferred from cluster)")
    parser.add_argument("--security-groups", help="Comma-separated security group IDs (optional, can be inferred)")
    parser.add_argument("--list-tasks", action="store_true", help="List recent ECS tasks and exit")
    parser.add_argument(
        "--list-task-definitions",
        nargs="?",
        const="",  # If flag is present without value, use empty string (list all)
        default=None,  # If flag is not present, None
        metavar="PREFIX",
        help="List available ECS task definitions and exit. Optionally filter by prefix (e.g., scaffold-dev-)",
    )
    parser.add_argument(
        "--list-vpcs",
        action="store_true",
        help="List available VPCs and subnets and exit",
    )

    args = parser.parse_args()

    # Get region (used by all commands)
    region = args.region
    if region is None:
        session = boto3.Session()
        region = session.region_name

    # Handle listing commands before requiring a script
    if args.list_tasks or args.list_task_definitions is not None or args.list_vpcs:
        if region is None:
            print("Error: No AWS region specified.", file=sys.stderr)
            sys.exit(1)

        if args.list_tasks:
            list_ecs_tasks(region)
        elif args.list_task_definitions is not None:
            list_task_definitions(region, prefix=args.list_task_definitions or None)
        elif args.list_vpcs:
            list_vpcs(region)
        sys.exit(0)

    # Script is required for running
    if not args.script:
        parser.error("script is required unless using --list-tasks, --list-task-definitions, or --list-vpcs")

    # Read the script file
    script_path = Path(args.script)
    if not script_path.exists():
        print(f"Error: Script file '{args.script}' not found", file=sys.stderr)
        sys.exit(1)

    with open(script_path, "r") as f:
        script_content = f.read()

    # Detect script type
    script_type = _detect_script_type(script_path, script_content)

    # Validate region
    if region is None:
        print(
            "Error: No AWS region specified. Set AWS_DEFAULT_REGION, configure a profile, or use --region",
            file=sys.stderr,
        )
        sys.exit(1)

    # Common logging
    print(f"[cloud_run] Script: {script_path}", file=sys.stderr)
    print(f"[cloud_run] Script type: {script_type}", file=sys.stderr)
    print(f"[cloud_run] Region: {region}", file=sys.stderr)
    print(
        f"[cloud_run] Backend: {'ECS Fargate' if args.ecs else 'Lambda'}",
        file=sys.stderr,
    )

    # Parse environment variables
    env_vars = {}
    if args.env_vars:
        for env_var in args.env_vars:
            if "=" not in env_var:
                print(f"Error: Environment variable '{env_var}' must be in KEY=VALUE format", file=sys.stderr)
                sys.exit(1)
            key, value = env_var.split("=", 1)
            env_vars[key] = value

    # Secrets are just names/ARNs - they'll be fetched and expanded in ecs_infra
    secrets = args.secrets or []

    if args.ecs:
        # Require --cluster for ECS
        if not args.cluster:
            print(
                "Error: --cluster is required for ECS tasks. Use --cluster <name>",
                file=sys.stderr,
            )
            sys.exit(1)
        
        # Parse subnets and security groups if provided
        subnet_ids = args.subnets.split(",") if args.subnets else None
        security_group_ids = args.security_groups.split(",") if args.security_groups else None
        run_on_ecs(
            script_content,
            script_type,
            args.script_args,
            region,
            args.cpu,
            args.memory,
            args.task_definition,
            args.cluster,
            args.vpc,
            subnet_ids,
            security_group_ids,
            args.create_cluster,
            env_vars,
            secrets,
            args.runtime_secrets,
        )
    else:
        function_name = args.function_name or f"cloud-run-script-{script_type}"
        run_on_lambda(script_content, script_type, args.script_args, region, function_name)


if __name__ == "__main__":
    main()
