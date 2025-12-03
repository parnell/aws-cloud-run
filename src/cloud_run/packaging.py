from __future__ import annotations

import io
import os
from typing import Optional
import zipfile


def _write_handler_py() -> str:
    """Return the handler source code that runs inside AWS Lambda.

    The handler loads the user function from func.pkl using cloudpickle,
    deserializes the (args, kwargs) from event['payload'] (base64-encoded
    cloudpickle bytes), executes the function, and returns a JSON-serializable
    envelope with a base64-encoded cloudpickle result or exception.
    """

    return (
        "import base64\n"
        "import json\n"
        "import traceback\n"
        "import sys\n"
        "import os\n"
        "\n"
        "print('[INIT] Handler module loading...', flush=True)\n"
        "print(f'[INIT] Python version: {sys.version}', flush=True)\n"
        "print(f'[INIT] Working directory: {os.getcwd()}', flush=True)\n"
        "print(f'[INIT] Directory contents: {os.listdir(\".\")}', flush=True)\n"
        "\n"
        "print('[INIT] Importing cloudpickle...', flush=True)\n"
        "import cloudpickle\n"
        "print(f'[INIT] cloudpickle version: {cloudpickle.__version__}', flush=True)\n"
        "\n"
        "# Check func.pkl file\n"
        "print('[INIT] Checking func.pkl...', flush=True)\n"
        "if os.path.exists('func.pkl'):\n"
        "    pkl_size = os.path.getsize('func.pkl')\n"
        "    print(f'[INIT] func.pkl exists, size: {pkl_size} bytes', flush=True)\n"
        "else:\n"
        "    print('[INIT] ERROR: func.pkl does not exist!', flush=True)\n"
        "\n"
        "print('[INIT] Handler module loaded successfully', flush=True)\n"
        "\n"
        "def _load_func():\n"
        "    print('[LOAD] Loading function from func.pkl...', flush=True)\n"
        "    try:\n"
        "        with open('func.pkl', 'rb') as f:\n"
        "            pkl_bytes = f.read()\n"
        "        print(f'[LOAD] Read {len(pkl_bytes)} bytes from func.pkl', flush=True)\n"
        "        print('[LOAD] Deserializing with cloudpickle...', flush=True)\n"
        "        func = cloudpickle.loads(pkl_bytes)\n"
        "        print(f'[LOAD] Function loaded: {func}', flush=True)\n"
        "        print(f'[LOAD] Function name: {getattr(func, \"__name__\", \"unknown\")}', flush=True)\n"
        "        print(f'[LOAD] Function module: {getattr(func, \"__module__\", \"unknown\")}', flush=True)\n"
        "        return func\n"
        "    except Exception as e:\n"
        "        print(f'[LOAD] ERROR loading function: {type(e).__name__}: {e}', flush=True)\n"
        "        traceback.print_exc()\n"
        "        raise RuntimeError(f'Failed to load function from func.pkl: {e}') from e\n"
        "\n"
        "def lambda_handler(event, context):\n"
        "    print('[HANDLER] Lambda handler invoked', flush=True)\n"
        "    print(f'[HANDLER] Event type: {type(event).__name__}', flush=True)\n"
        "    print(f'[HANDLER] Event keys: {list(event.keys()) if isinstance(event, dict) else \"N/A\"}', flush=True)\n"
        "    try:\n"
        "        if not isinstance(event, dict):\n"
        "            raise ValueError(f'Expected event to be a dict, got {type(event).__name__}')\n"
        "        payload_b64 = event.get('payload')\n"
        "        if payload_b64 is None:\n"
        "            raise ValueError('Missing payload in event')\n"
        "        if not isinstance(payload_b64, str):\n"
        "            raise ValueError(f'Expected payload to be a string, got {type(payload_b64).__name__}')\n"
        "        print(f'[HANDLER] Payload length: {len(payload_b64)} chars', flush=True)\n"
        "        try:\n"
        "            print('[HANDLER] Decoding payload...', flush=True)\n"
        "            payload_bytes = base64.b64decode(payload_b64)\n"
        "            print(f'[HANDLER] Decoded {len(payload_bytes)} bytes', flush=True)\n"
        "            print('[HANDLER] Deserializing args/kwargs...', flush=True)\n"
        "            args, kwargs = cloudpickle.loads(payload_bytes)\n"
        "            print(f'[HANDLER] Args: {len(args)} positional, {len(kwargs)} keyword', flush=True)\n"
        "        except Exception as e:\n"
        "            print(f'[HANDLER] ERROR deserializing payload: {e}', flush=True)\n"
        "            raise ValueError(f'Failed to deserialize payload: {e}') from e\n"
        "        try:\n"
        "            print('[HANDLER] Loading function...', flush=True)\n"
        "            fn = _load_func()\n"
        "            print('[HANDLER] Function loaded successfully', flush=True)\n"
        "        except Exception as e:\n"
        "            print(f'[HANDLER] ERROR loading function: {e}', flush=True)\n"
        "            raise RuntimeError(f'Failed to load function: {e}') from e\n"
        "        try:\n"
        "            print('[HANDLER] Executing function...', flush=True)\n"
        "            result = fn(*args, **kwargs)\n"
        "            print(f'[HANDLER] Function returned: {type(result).__name__}', flush=True)\n"
        "        except Exception as e:\n"
        "            print(f'[HANDLER] ERROR executing function: {type(e).__name__}: {e}', flush=True)\n"
        "            raise\n"
        "        try:\n"
        "            print('[HANDLER] Serializing result...', flush=True)\n"
        "            result_b64 = base64.b64encode(cloudpickle.dumps(result)).decode('utf-8')\n"
        "            print('[HANDLER] Result serialized successfully', flush=True)\n"
        "        except Exception as e:\n"
        "            print(f'[HANDLER] ERROR serializing result: {e}', flush=True)\n"
        "            raise RuntimeError(f'Failed to serialize result: {e}') from e\n"
        "        print('[HANDLER] Returning success response', flush=True)\n"
        "        return {\n"
        "            'ok': True,\n"
        "            'result': result_b64,\n"
        "        }\n"
        "    except Exception as e:\n"
        "        print(f'[HANDLER] Caught exception: {type(e).__name__}: {e}', flush=True)\n"
        "        try:\n"
        "            tb = traceback.format_exc()\n"
        "            print(f'[HANDLER] Traceback:\\n{tb}', flush=True)\n"
        "        except Exception:\n"
        "            tb = f'Traceback capture failed. Exception: {type(e).__name__}: {e}'\n"
        "        \n"
        "        error_b64 = None\n"
        "        try:\n"
        "            error_b64 = base64.b64encode(cloudpickle.dumps(e)).decode('utf-8')\n"
        "        except Exception:\n"
        "            try:\n"
        "                error_b64 = base64.b64encode(cloudpickle.dumps(Exception(str(e)))).decode('utf-8')\n"
        "            except Exception:\n"
        "                try:\n"
        "                    error_b64 = base64.b64encode(cloudpickle.dumps(RuntimeError(str(e)))).decode('utf-8')\n"
        "                except Exception:\n"
        "                    pass\n"
        "        \n"
        "        error_response = {\n"
        "            'ok': False,\n"
        "            'error_message': str(e) if e else 'Unknown error',\n"
        "            'error_type': type(e).__name__ if e else 'Exception',\n"
        "            'traceback': tb,\n"
        "        }\n"
        "        \n"
        "        if error_b64:\n"
        "            error_response['error'] = error_b64\n"
        "        \n"
        "        print('[HANDLER] Returning error response', flush=True)\n"
        "        return error_response\n"
    )


def _add_cloudpickle_to_zip(zip_file: zipfile.ZipFile) -> None:
    """Embed the cloudpickle package into the deployment zip.

    This ensures the Lambda runtime can import cloudpickle even if it is not
    part of the base runtime. cloudpickle is pure-Python, so it's safe to vend.
    """

    import cloudpickle  # type: ignore

    module_path = os.path.dirname(cloudpickle.__file__)  # .../cloudpickle

    for root, _dirs, files in os.walk(module_path):
        for file_name in files:
            if not file_name.endswith(".py") and not file_name.endswith(".pyi"):
                # Only include Python sources and type hints
                continue
            full_path = os.path.join(root, file_name)
            # Compute archive name inside zip to preserve package structure
            arcname = os.path.relpath(full_path, os.path.dirname(module_path))
            zip_file.write(full_path, arcname)


def _add_module_to_zip(zip_file: zipfile.ZipFile, module_path: str) -> None:
    """Add a Python module to the zip file.

    Parameters
    - module_path: Path to the module file (e.g., '/path/to/shell_runner.py')
    """
    module_name = os.path.splitext(os.path.basename(module_path))[0]
    with open(module_path, "rb") as f:
        zip_file.writestr(f"{module_name}.py", f.read())


def build_deployment_zip(
    serialized_func: bytes, include_modules: Optional[list[str]] = None
) -> bytes:
    """Create a deployment zip containing handler, func.pkl, cloudpickle, and optional modules.

    Parameters
    - serialized_func: cloudpickle.dumps(func)
    - include_modules: Optional list of module file paths to include in the zip

    Returns
    - Zip file bytes suitable for AWS Lambda Create/UpdateFunctionCode.
    """

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write handler
        zf.writestr("handler.py", _write_handler_py())
        # Write serialized function
        zf.writestr("func.pkl", serialized_func)
        # Vendor cloudpickle package
        _add_cloudpickle_to_zip(zf)
        # Add optional modules
        if include_modules:
            for module_path in include_modules:
                _add_module_to_zip(zf, module_path)

    return buffer.getvalue()
