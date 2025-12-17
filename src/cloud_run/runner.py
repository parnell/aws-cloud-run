from __future__ import annotations

import base64
import json
import re
import sys
import time
from typing import Any

import boto3
import cloudpickle  # type: ignore
from botocore.exceptions import ClientError

from .aws_infra import ensure_lambda, ensure_role
from .packaging import build_deployment_zip


def _get_lambda_logs(
    lambda_client: Any, function_name: str, region_name: str | None = None
) -> str | None:
    """Try to fetch recent CloudWatch logs for a Lambda function."""
    try:
        logs_client = boto3.client("logs", region_name=region_name)
        log_group_name = f"/aws/lambda/{function_name}"

        # Get the most recent log stream
        streams = logs_client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy="LastEventTime",
            descending=True,
            limit=1,
        )

        if not streams.get("logStreams"):
            return None

        log_stream_name = streams["logStreams"][0]["logStreamName"]

        # Get recent log events
        events = logs_client.get_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            limit=50,
        )

        if not events.get("events"):
            return None

        # Format log events
        log_lines = []
        for event in events["events"]:
            log_lines.append(event["message"])

        return "\n".join(log_lines)
    except Exception:
        # If we can't get logs, that's okay - return None
        return None


def _default_function_name(func: Any) -> str:
    module = getattr(func, "__module__", "user")
    name = getattr(func, "__name__", "callable")
    raw = f"pi-cloud-run-{module}.{name}"
    # Lambda name constraints: letters, numbers, hyphens; <= 64 chars
    safe = re.sub(r"[^A-Za-z0-9-]", "-", raw)
    return safe[:64]


def _wait_for_lambda_ready(lambda_client: Any, function_name: str, max_wait: int = 60) -> None:
    """Wait for Lambda function to be in Active state before invoking."""
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            response = lambda_client.get_function(FunctionName=function_name)
            state = response["Configuration"]["State"]
            if state == "Active":
                return
            elif state in ("Failed", "Inactive"):
                raise RuntimeError(f"Lambda function {function_name} is in {state} state")
            # State is Pending or PendingUpdate, wait a bit
            time.sleep(1)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "ResourceNotFoundException":
                # Function might not be created yet, wait a bit
                time.sleep(1)
            else:
                raise

    raise RuntimeError(
        f"Lambda function {function_name} did not become Active within {max_wait} seconds"
    )


def run(
    func: Any,
    *args: Any,
    function_name: str | None = None,
    role_name: str = "pi-cloud-runner-role",
    region_name: str | None = None,
    runtime: str = "python3.12",
    timeout: int = 900,
    memory_size: int = 512,
    ephemeral_storage_mb: int = 512,
    architecture: str = "x86_64",
    include_modules: list[str] | None = None,
    **kwargs: Any,
) -> Any:
    """Run a Python callable in AWS Lambda and return its result.

    Arguments and return value are serialized with cloudpickle to support
    arbitrary Python objects. Exceptions raised in Lambda are re-raised locally
    with the remote traceback included in the message.
    """

    # Log function details before serialization
    print(f"[LOCAL] Function to serialize: {func}", file=sys.stderr)
    print(f"[LOCAL] Function name: {getattr(func, '__name__', 'unknown')}", file=sys.stderr)
    print(f"[LOCAL] Function module: {getattr(func, '__module__', 'unknown')}", file=sys.stderr)
    print(f"[LOCAL] Function qualname: {getattr(func, '__qualname__', 'unknown')}", file=sys.stderr)

    # Check function's globals for problematic references
    if hasattr(func, "__globals__"):
        global_keys = list(func.__globals__.keys())
        print(f"[LOCAL] Function globals keys: {global_keys}", file=sys.stderr)

    # Serialize the function separately from the invocation args to allow re-use
    print("[LOCAL] Serializing function with cloudpickle...", file=sys.stderr)
    serialized_func = cloudpickle.dumps(func)
    print(f"[LOCAL] Serialized function size: {len(serialized_func)} bytes", file=sys.stderr)

    # Try to deserialize locally to catch errors early
    print("[LOCAL] Testing local deserialization...", file=sys.stderr)
    try:
        test_func = cloudpickle.loads(serialized_func)
        print(f"[LOCAL] Local deserialization succeeded: {test_func}", file=sys.stderr)
    except Exception as e:
        print(f"[LOCAL] WARNING: Local deserialization failed: {e}", file=sys.stderr)

    zip_bytes = build_deployment_zip(serialized_func, include_modules=include_modules)
    print(f"[LOCAL] Deployment zip size: {len(zip_bytes)} bytes", file=sys.stderr)

    # Ensure IAM role and Lambda function
    if function_name is None:
        function_name = _default_function_name(func)
    role_arn = ensure_role(role_name, region_name=region_name)
    ensure_lambda(
        function_name=function_name,
        role_arn=role_arn,
        zip_bytes=zip_bytes,
        region_name=region_name,
        runtime=runtime,
        timeout=timeout,
        memory_size=memory_size,
        ephemeral_storage_mb=ephemeral_storage_mb,
        architecture=architecture,
    )

    # Wait for Lambda function to be ready (Active state)
    lambda_client = boto3.client("lambda", region_name=region_name)
    _wait_for_lambda_ready(lambda_client, function_name)

    # Prepare invocation payload: base64-encoded cloudpickle of (args, kwargs)
    payload = base64.b64encode(cloudpickle.dumps((args, kwargs))).decode("utf-8")
    event = {"payload": payload}

    try:
        resp = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(event).encode("utf-8"),
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        raise RuntimeError(
            f"Failed to invoke Lambda function {function_name}: {error_code} - {error_message}"
        )

    # Read the response payload once
    raw_payload = resp["Payload"].read()

    # Check for Lambda invocation errors (runtime errors, handler not found, etc.)
    function_error = resp.get("FunctionError")
    if function_error:
        payload_text = raw_payload.decode("utf-8", errors="replace")

        # Try to get CloudWatch logs for more context
        logs = _get_lambda_logs(lambda_client, function_name, region_name)

        error_msg = (
            f"Lambda function {function_name} failed with {function_error}.\n"
            f"Response payload: {payload_text}"
        )
        if logs:
            error_msg += f"\n\nCloudWatch Logs:\n{logs}"

        raise RuntimeError(error_msg)

    try:
        result_obj = json.loads(raw_payload)
    except json.JSONDecodeError as e:
        payload_text = raw_payload.decode("utf-8", errors="replace")
        logs = _get_lambda_logs(lambda_client, function_name, region_name)

        error_msg = (
            f"Lambda function {function_name} returned invalid JSON response.\n"
            f"JSON decode error: {e}\n"
            f"Response payload: {payload_text}"
        )
        if logs:
            error_msg += f"\n\nCloudWatch Logs:\n{logs}"

        raise RuntimeError(error_msg)

    # Check if the response has the expected structure
    if not isinstance(result_obj, dict):
        logs = _get_lambda_logs(lambda_client, function_name, region_name)
        error_msg = (
            f"Lambda function {function_name} returned unexpected response type: {type(result_obj)}\n"
            f"Response: {result_obj}"
        )
        if logs:
            error_msg += f"\n\nCloudWatch Logs:\n{logs}"
        raise RuntimeError(error_msg)

    # Handle error responses from the handler
    if not result_obj.get("ok"):
        tb = result_obj.get("traceback", "No traceback available")
        exc_b64 = result_obj.get("error")
        error_message = result_obj.get("error_message", "Unknown error")
        error_type = result_obj.get("error_type", "Exception")

        if not exc_b64:
            # Missing error field - this shouldn't happen but handle gracefully
            logs = _get_lambda_logs(lambda_client, function_name, region_name)
            error_msg = (
                f"Lambda function {function_name} returned error response but missing error field.\n"
                f"Error type: {error_type}\n"
                f"Error message: {error_message}\n"
                f"Traceback: {tb}"
            )
            if logs:
                error_msg += f"\n\nCloudWatch Logs:\n{logs}"
            raise RuntimeError(error_msg)

        try:
            exc = cloudpickle.loads(base64.b64decode(exc_b64))
        except Exception as e:
            # If we can't deserialize the exception, use the error message and type
            logs = _get_lambda_logs(lambda_client, function_name, region_name)
            error_msg = (
                f"Lambda function {function_name} raised {error_type}: {error_message}\n"
                f"Failed to deserialize exception: {e}\n"
                f"Remote traceback:\n{tb}"
            )
            if logs:
                error_msg += f"\n\nCloudWatch Logs:\n{logs}"
            raise RuntimeError(error_msg)

        # Attach remote traceback context
        raise RuntimeError(f"Lambda error: {exc}\nRemote traceback:\n{tb}")

    # Handle successful response
    if "result" not in result_obj:
        logs = _get_lambda_logs(lambda_client, function_name, region_name)
        error_msg = (
            f"Lambda function {function_name} returned success response but missing result field.\n"
            f"Response: {result_obj}"
        )
        if logs:
            error_msg += f"\n\nCloudWatch Logs:\n{logs}"
        raise RuntimeError(error_msg)

    result_b64 = result_obj["result"]
    try:
        return cloudpickle.loads(base64.b64decode(result_b64))
    except Exception as e:
        logs = _get_lambda_logs(lambda_client, function_name, region_name)
        error_msg = (
            f"Lambda function {function_name} returned result but failed to deserialize: {e}\n"
            f"Result (base64): {result_b64[:200]}..."
        )
        if logs:
            error_msg += f"\n\nCloudWatch Logs:\n{logs}"
        raise RuntimeError(error_msg)
