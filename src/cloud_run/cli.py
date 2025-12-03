"""CLI for running shell scripts and Python scripts on AWS Lambda"""

import argparse
import json
import sys
import time
from pathlib import Path

import boto3

from .aws_infra import ensure_lambda, ensure_role


def _build_script_handler(script_type: str) -> str:
    """Generate Lambda handler source code for running scripts.
    
    This embeds the runner logic directly in the handler, avoiding cloudpickle entirely.
    """
    if script_type == 'python':
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


def _build_deployment_zip(handler_code: str) -> bytes:
    """Create a minimal deployment zip with just the handler."""
    import io
    import zipfile
    
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", handler_code)
    return buffer.getvalue()


def _detect_script_type(script_path: Path, script_content: str) -> str:
    """Detect whether a script is Python or shell based on extension and shebang.
    
    Returns: 'python' or 'shell'
    """
    # Check file extension first
    ext = script_path.suffix.lower()
    if ext == '.py':
        return 'python'
    elif ext in ('.sh', '.bash'):
        return 'shell'
    
    # Check shebang
    first_line = script_content.split('\n')[0].strip()
    if first_line.startswith('#!'):
        if 'python' in first_line.lower():
            return 'python'
        elif any(shell in first_line.lower() for shell in ['sh', 'bash', 'zsh', 'fish']):
            return 'shell'
    
    # Default to shell for backward compatibility
    return 'shell'


def main():
    parser = argparse.ArgumentParser(
        description='Run a shell script or Python script on AWS Lambda'
    )
    parser.add_argument(
        'script',
        help='Path to the script to run (Python .py or shell script)'
    )
    parser.add_argument(
        'args',
        nargs='*',
        help='Arguments to pass to the script'
    )
    parser.add_argument(
        '--function-name',
        help='Lambda function name (default: auto-generated)'
    )
    parser.add_argument(
        '--region',
        default='us-east-2',
        help='AWS region (default: us-east-2)'
    )
    
    args = parser.parse_args()
    
    # Read the script file
    script_path = Path(args.script)
    if not script_path.exists():
        print(f"Error: Script file '{args.script}' not found", file=sys.stderr)
        sys.exit(1)
    
    with open(script_path, 'r') as f:
        script_content = f.read()
    
    # Detect script type
    script_type = _detect_script_type(script_path, script_content)
    
    # Generate function name if not provided
    if args.function_name:
        function_name = args.function_name
    else:
        function_name = f"cloud-run-script-{script_type}"
    
    try:
        # Build deployment package with embedded runner (no cloudpickle!)
        print(f"[cloud_run] Script: {script_path}", file=sys.stderr)
        print(f"[cloud_run] Script type: {script_type}", file=sys.stderr)
        print(f"[cloud_run] Region: {args.region}", file=sys.stderr)
        print(f"[cloud_run] Function name: {function_name}", file=sys.stderr)
        print("[cloud_run] Building deployment package...", file=sys.stderr)
        handler_code = _build_script_handler(script_type)
        zip_bytes = _build_deployment_zip(handler_code)
        print(f"[cloud_run] Deployment package size: {len(zip_bytes)} bytes", file=sys.stderr)
        
        # Ensure IAM role and Lambda function
        print("[cloud_run] Ensuring IAM role exists...", file=sys.stderr)
        role_arn = ensure_role("pi-cloud-runner-role", region_name=args.region)
        print(f"[cloud_run] Role ARN: {role_arn}", file=sys.stderr)
        
        print(f"[cloud_run] Deploying Lambda function: {function_name}", file=sys.stderr)
        ensure_lambda(
            function_name=function_name,
            role_arn=role_arn,
            zip_bytes=zip_bytes,
            region_name=args.region,
            runtime="python3.12",
            timeout=900,
            memory_size=512,
        )
        print("[cloud_run] Lambda function deployed", file=sys.stderr)
        
        # Invoke Lambda with script content as plain JSON (no cloudpickle!)
        lambda_client = boto3.client("lambda", region_name=args.region)
        
        # Wait for function to be ready
        print("[cloud_run] Waiting for function to be ready...", file=sys.stderr)
        for i in range(30):
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
            "args": list(args.args),
        }
        
        print("[cloud_run] Invoking Lambda function...", file=sys.stderr)
        invoke_start = time.time()
        resp = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(event).encode("utf-8"),
        )
        invoke_duration = time.time() - invoke_start
        print(f"[cloud_run] Lambda invocation complete, status: {resp.get('StatusCode')}, duration: {invoke_duration:.2f}s", file=sys.stderr)
        
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
        if result.get('stdout'):
            print(result['stdout'], end='')
        if result.get('stderr'):
            print(result['stderr'], end='', file=sys.stderr)
        
        # Exit with the script's return code
        sys.exit(result.get('returncode', 0))
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

