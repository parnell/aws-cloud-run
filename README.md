# aws-cloud-run

Run Python or shell scripts on AWS Lambda (default) or ECS Fargate (for longer jobs).

This project provides:

- A CLI: `cloud_run <script> [args...]`
- A Python API: `from cloud_run import run`
- Automatic AWS infrastructure setup for Lambda and ECS paths
- Log streaming and log file capture for ECS runs

## What It Does

- Executes `.py`, `.sh`, and `.bash` scripts remotely
- Detects script type by extension or shebang
- Uses Lambda by default (up to 15 minutes)
- Uses ECS Fargate with `--ecs` for long-running tasks
- Supports environment variables and AWS Secrets Manager injection

## Prerequisites

- Python `>=3.13` for local development
- AWS credentials configured for `boto3`
- AWS region configured (`AWS_DEFAULT_REGION`, profile config, or `--region`)

If you use AWS SSO, see `AWS_SSO_SETUP.md`.

## Installation

### With uv (recommended)

```bash
uv sync --dev
```

### Editable install with pip

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## CLI Usage

```bash
uv run cloud_run --help
```

### Lambda (default)

```bash
uv run cloud_run examples/hello.py
uv run cloud_run examples/hello.sh
```

Pass script arguments:

```bash
uv run cloud_run examples/hello.py foo bar
```

Set environment variables:

```bash
uv run cloud_run examples/hello.py -e STAGE=dev -e DEBUG=true
```

### ECS Fargate (for long jobs)

`--cluster` is required for ECS runs:

```bash
uv run cloud_run examples/hello.py --ecs --cluster my-ecs-cluster --create-cluster --vpc vpc-123456
```

You can also provide subnets/security groups directly:

```bash
uv run cloud_run examples/hello.sh --ecs --cluster my-ecs-cluster --subnets subnet-a,subnet-b --security-groups sg-123
```

Use an existing task definition:

```bash
uv run cloud_run examples/hello.py --ecs --cluster my-ecs-cluster --task-definition my-family:12
```

When your IAM role lacks `ecs:DescribeTaskDefinition` (e.g. Scaffold task-runner SSO), pass the container name explicitly. `--log-group` is optional and defaults to `/ecs/<family>`. Task-runner also cannot infer subnets from the cluster — pass network config explicitly (same values as `run_ecs_task.py` for prod):

```bash
uv run cloud_run examples/hello.py --ecs --cluster scaffold-prod-ecs-cluster \
  --task-definition scaffold-prod-analyze-job \
  --container-name scaffold-prod-analyze-job \
  --log-group /scaffold/prod/app-log-group \
  --subnets subnet-04c898c816719788b,subnet-01a214e33fc40745d,subnet-0b3582fd6e3e292bf \
  --security-groups sg-016da43d0257b500e \
  --assign-public-ip disabled
```

### ECS Discovery Commands

```bash
uv run cloud_run --list-vpcs --region us-east-1
uv run cloud_run --list-tasks --region us-east-1
uv run cloud_run --list-task-definitions --region us-east-1
uv run cloud_run --list-task-definitions scaffold-dev- --region us-east-1
```

## Secrets

Two secret modes are supported:

- `--secret SECRET_NAME`
  - Fetches secret locally and injects key/value pairs into ECS container overrides.
  - Counts toward ECS 8KB override limit.
- `--runtime-secret SECRET_NAME`
  - Fetches secret inside the container at runtime.
  - Avoids most override-size pressure (requires `boto3` in container runtime).

Both expect JSON object secrets (key/value pairs).

## Python API

Use the API when you want to run a Python callable via Lambda and get a return value back:

```python
from cloud_run import run

def multiply(a, b):
    return a * b

result = run(
    multiply,
    6,
    7,
    region_name="us-east-1",
    function_name="pi-cloud-run-multiply",
)
print(result)  # 42
```

The API serializes arguments/return values with `cloudpickle`, provisions IAM/Lambda as needed, invokes synchronously, and re-raises remote errors with traceback context.

## Development

Run tests:

```bash
uv run pytest -v tests
```

Build package:

```bash
uv build
```

Pre-commit hooks:

```bash
uv run pre-commit run --all-files
```

## Notes

- ECS run logs are written to `logs/<task-id>.log` in addition to terminal output.
- For ECS, subnets can be inferred from cluster services/tasks, but explicit `--subnets` is most reliable.
- Lambda runtime used by this project is Python `3.12` for remote execution.
