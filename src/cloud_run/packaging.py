from __future__ import annotations

import base64
import io
import os
import sys
import types
import typing as t
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
        "import cloudpickle\n"
        "\n"
        "def _load_func():\n"
        "    with open('func.pkl', 'rb') as f:\n"
        "        return cloudpickle.loads(f.read())\n"
        "\n"
        "def lambda_handler(event, context):\n"
        "    try:\n"
        "        payload_b64 = event.get('payload')\n"
        "        if payload_b64 is None:\n"
        "            raise ValueError('Missing payload')\n"
        "        args, kwargs = cloudpickle.loads(base64.b64decode(payload_b64))\n"
        "        fn = _load_func()\n"
        "        result = fn(*args, **kwargs)\n"
        "        return {\n"
        "            'ok': True,\n"
        "            'result': base64.b64encode(cloudpickle.dumps(result)).decode('utf-8'),\n"
        "        }\n"
        "    except Exception as e:\n"
        "        tb = traceback.format_exc()\n"
        "        return {\n"
        "            'ok': False,\n"
        "            'error': base64.b64encode(cloudpickle.dumps(e)).decode('utf-8'),\n"
        "            'traceback': tb,\n"
        "        }\n"
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
            if not file_name.endswith('.py') and not file_name.endswith('.pyi'):
                # Only include Python sources and type hints
                continue
            full_path = os.path.join(root, file_name)
            # Compute archive name inside zip to preserve package structure
            arcname = os.path.relpath(full_path, os.path.dirname(module_path))
            zip_file.write(full_path, arcname)


def build_deployment_zip(serialized_func: bytes) -> bytes:
    """Create a deployment zip containing handler, func.pkl, and cloudpickle.

    Parameters
    - serialized_func: cloudpickle.dumps(func)

    Returns
    - Zip file bytes suitable for AWS Lambda Create/UpdateFunctionCode.
    """

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        # Write handler
        zf.writestr('handler.py', _write_handler_py())
        # Write serialized function
        zf.writestr('func.pkl', serialized_func)
        # Vendor cloudpickle package
        _add_cloudpickle_to_zip(zf)

    return buffer.getvalue()


