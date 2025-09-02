from __future__ import annotations

import base64
import json
import re
from typing import Any, Optional

import boto3
import cloudpickle  # type: ignore

from .aws_infra import ensure_lambda, ensure_role
from .packaging import build_deployment_zip


def _default_function_name(func: Any) -> str:
    module = getattr(func, "__module__", "user")
    name = getattr(func, "__name__", "callable")
    raw = f"pi-cloud-run-{module}.{name}"
    # Lambda name constraints: letters, numbers, hyphens; <= 64 chars
    safe = re.sub(r"[^A-Za-z0-9-]", "-", raw)
    return safe[:64]


def run(
    func: Any,
    *args: Any,
    function_name: Optional[str] = None,
    role_name: str = "pi-cloud-runner-role",
    region_name: Optional[str] = None,
    runtime: str = "python3.12",
    timeout: int = 900,
    memory_size: int = 512,
    ephemeral_storage_mb: int = 512,
    architecture: str = "x86_64",
    **kwargs: Any,
) -> Any:
    """Run a Python callable in AWS Lambda and return its result.

    Arguments and return value are serialized with cloudpickle to support
    arbitrary Python objects. Exceptions raised in Lambda are re-raised locally
    with the remote traceback included in the message.
    """

    # Serialize the function separately from the invocation args to allow re-use
    serialized_func = cloudpickle.dumps(func)
    zip_bytes = build_deployment_zip(serialized_func)

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

    # Prepare invocation payload: base64-encoded cloudpickle of (args, kwargs)
    payload = base64.b64encode(cloudpickle.dumps((args, kwargs))).decode("utf-8")
    event = {"payload": payload}

    lambda_client = boto3.client("lambda", region_name=region_name)
    resp = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode("utf-8"),
    )

    raw_payload = resp["Payload"].read()
    result_obj = json.loads(raw_payload)

    if not result_obj.get("ok"):
        tb = result_obj.get("traceback")
        exc_b64 = result_obj.get("error")
        try:
            exc = cloudpickle.loads(base64.b64decode(exc_b64))
        except Exception:  # pragma: no cover - fallback if unpickle fails
            exc = RuntimeError("Remote exception could not be deserialized")
        # Attach remote traceback context
        raise RuntimeError(f"Lambda error: {exc}\nRemote traceback:\n{tb}")

    result_b64 = result_obj["result"]
    return cloudpickle.loads(base64.b64decode(result_b64))


