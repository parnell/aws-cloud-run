"""Standalone shell script runner for Lambda - no cloud_run dependencies"""


def run_shell_script(script_content: str, *args: str) -> dict:
    """Execute a shell script on AWS Lambda.
    
    This function is designed to be serialized and run on Lambda.
    It has no dependencies on the cloud_run module itself.
    Imports are done inside the function to avoid cloudpickle serialization issues.
    """
    import subprocess
    import os
    
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

