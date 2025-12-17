"""Lambda execution utilities for cloud_run."""

import io
import json
import sys
import time
import zipfile

import boto3

from .aws_infra import ensure_lambda, ensure_role


def build_script_handler(script_type: str) -> str:
    """Generate Lambda handler source code for running scripts.

    This embeds the runner logic directly in the handler, avoiding cloudpickle entirely.
    """
    if script_type == "python":
        return '''
import json
import sys
import io
import contextlib

def lambda_handler(event, context):
    """Execute a Python script passed in the event."""
    script_content = event.get('script_content', '')
    args = event.get('args', [])
    
    # Remove shebang if present
    lines = script_content.split('\\n')
    if lines and lines[0].startswith('#!'):
        script_content = '\\n'.join(lines[1:])
    
    # Capture stdout and stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    
    # Set up sys.argv
    original_argv = sys.argv
    try:
        sys.argv = ['script.py'] + list(args)
        
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            try:
                code = compile(script_content, '<script>', 'exec')
                exec(code, {'__name__': '__main__', '__file__': 'script.py'})
                returncode = 0
            except SystemExit as e:
                returncode = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            except Exception:
                import traceback
                traceback.print_exc(file=stderr_capture)
                returncode = 1
        
        return {
            'stdout': stdout_capture.getvalue(),
            'stderr': stderr_capture.getvalue(),
            'returncode': returncode,
        }
    finally:
        sys.argv = original_argv
'''
    else:  # shell
        return '''
import json
import subprocess
import os

def lambda_handler(event, context):
    """Execute a shell script passed in the event."""
    script_content = event.get('script_content', '')
    args = event.get('args', [])
    
    script_path = '/tmp/script.sh'
    
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    os.chmod(script_path, 0o755)
    
    try:
        result = subprocess.run(
            ['/bin/bash', script_path] + list(args),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
        }
    finally:
        if os.path.exists(script_path):
            os.unlink(script_path)
'''


def build_deployment_zip(handler_code: str) -> bytes:
    """Create a minimal deployment zip with just the handler."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", handler_code)
    return buffer.getvalue()


def run_on_lambda(
    script_content: str,
    script_type: str,
    script_args: list,
    region: str,
    function_name: str,
) -> None:
    """Run script on AWS Lambda."""
    try:
        print(f"[cloud_run] Function name: {function_name}", file=sys.stderr)
        print("[cloud_run] Building deployment package...", file=sys.stderr)
        handler_code = build_script_handler(script_type)
        zip_bytes = build_deployment_zip(handler_code)
        print(
            f"[cloud_run] Deployment package size: {len(zip_bytes)} bytes",
            file=sys.stderr,
        )

        # Ensure IAM role and Lambda function
        print("[cloud_run] Ensuring IAM role exists...", file=sys.stderr)
        role_arn = ensure_role("pi-cloud-runner-role", region_name=region)
        print(f"[cloud_run] Role ARN: {role_arn}", file=sys.stderr)

        print(f"[cloud_run] Deploying Lambda function: {function_name}", file=sys.stderr)
        ensure_lambda(
            function_name=function_name,
            role_arn=role_arn,
            zip_bytes=zip_bytes,
            region_name=region,
            runtime="python3.12",
            timeout=900,
            memory_size=512,
        )
        print("[cloud_run] Lambda function deployed", file=sys.stderr)

        # Invoke Lambda with script content as plain JSON
        lambda_client = boto3.client("lambda", region_name=region)

        # Wait for function to be ready
        print("[cloud_run] Waiting for function to be ready...", file=sys.stderr)
        for _ in range(30):
            resp = lambda_client.get_function(FunctionName=function_name)
            state = resp["Configuration"]["State"]
            if state == "Active":
                print("[cloud_run] Function is Active", file=sys.stderr)
                break
            print(f"[cloud_run] Function state: {state}, waiting...", file=sys.stderr)
            time.sleep(1)

        # Invoke
        event = {
            "script_content": script_content,
            "args": list(script_args),
        }

        print("[cloud_run] Invoking Lambda function...", file=sys.stderr)
        invoke_start = time.time()
        resp = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(event).encode("utf-8"),
        )
        invoke_duration = time.time() - invoke_start
        print(
            f"[cloud_run] Lambda invocation complete, status: {resp.get('StatusCode')}, duration: {invoke_duration:.2f}s",
            file=sys.stderr,
        )

        # Check for errors
        if resp.get("FunctionError"):
            payload = json.loads(resp["Payload"].read())
            error_msg = payload.get("errorMessage", "Unknown error")
            error_type = payload.get("errorType", "Unknown")
            print(f"[cloud_run] Lambda error type: {error_type}", file=sys.stderr)
            print(f"[cloud_run] Lambda error message: {error_msg}", file=sys.stderr)
            if "stackTrace" in payload:
                print("[cloud_run] Stack trace:", file=sys.stderr)
                for line in payload["stackTrace"]:
                    print(f"  {line}", file=sys.stderr)
            sys.exit(1)

        # Parse response
        result = json.loads(resp["Payload"].read())
        print("[cloud_run] Got result from Lambda", file=sys.stderr)

        # Print output
        if result.get("stdout"):
            print(result["stdout"], end="")
        if result.get("stderr"):
            print(result["stderr"], end="", file=sys.stderr)

        # Exit with the script's return code
        sys.exit(result.get("returncode", 0))

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
