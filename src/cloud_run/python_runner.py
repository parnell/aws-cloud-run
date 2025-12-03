"""Standalone Python script runner for Lambda - no cloud_run dependencies"""


def run_python_script(script_content: str, *args: str) -> dict:
    """Execute a Python script on AWS Lambda.
    
    This function is designed to be serialized and run on Lambda.
    It has no dependencies on the cloud_run module itself.
    Imports are done inside the function to avoid cloudpickle serialization issues.
    
    Instead of using subprocess (which can cause segfaults), we execute the Python
    code directly using exec() and capture stdout/stderr using StringIO.
    """
    import sys
    import io
    import contextlib
    
    # Remove shebang if present
    lines = script_content.split('\n')
    if lines and lines[0].startswith('#!'):
        script_content = '\n'.join(lines[1:])
    
    # Capture stdout and stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    
    # Set up sys.argv to match what the script would expect
    original_argv = sys.argv
    try:
        sys.argv = ['script.py'] + list(args)
        
        # Execute the script with captured output
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            try:
                # Compile and execute the script
                code = compile(script_content, '<script>', 'exec')
                exec(code, {'__name__': '__main__', '__file__': 'script.py'})
                returncode = 0
            except SystemExit as e:
                # Handle sys.exit() calls
                returncode = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            except Exception:
                # Any other exception - print to stderr and return error code
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

