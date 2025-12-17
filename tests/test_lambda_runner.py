"""Tests for Lambda runner utilities."""

import io
import zipfile

from cloud_run.lambda_runner import build_deployment_zip, build_script_handler


class TestBuildScriptHandler:
    """Tests for script handler generation."""

    def test_python_handler_is_valid_python(self):
        """Python handler code is syntactically valid."""
        handler = build_script_handler("python")
        # Should compile without errors
        compile(handler, "<handler>", "exec")

    def test_shell_handler_is_valid_python(self):
        """Shell handler code is syntactically valid."""
        handler = build_script_handler("shell")
        # Should compile without errors
        compile(handler, "<handler>", "exec")

    def test_python_handler_contains_lambda_handler(self):
        """Python handler defines lambda_handler function."""
        handler = build_script_handler("python")
        assert "def lambda_handler(event, context):" in handler

    def test_shell_handler_contains_lambda_handler(self):
        """Shell handler defines lambda_handler function."""
        handler = build_script_handler("shell")
        assert "def lambda_handler(event, context):" in handler

    def test_python_handler_uses_exec(self):
        """Python handler uses exec to run script."""
        handler = build_script_handler("python")
        assert "exec(" in handler

    def test_shell_handler_uses_subprocess(self):
        """Shell handler uses subprocess to run script."""
        handler = build_script_handler("shell")
        assert "subprocess" in handler
        assert "/bin/bash" in handler

    def test_handlers_return_dict_with_expected_keys(self):
        """Handlers should return stdout, stderr, returncode."""
        for script_type in ["python", "shell"]:
            handler = build_script_handler(script_type)
            assert "'stdout'" in handler or '"stdout"' in handler
            assert "'stderr'" in handler or '"stderr"' in handler
            assert "'returncode'" in handler or '"returncode"' in handler


class TestBuildDeploymentZip:
    """Tests for deployment zip creation."""

    def test_creates_valid_zip(self):
        """build_deployment_zip creates a valid zip file."""
        handler_code = build_script_handler("python")
        zip_bytes = build_deployment_zip(handler_code)

        # Should be readable as a zip file
        buffer = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buffer, "r") as zf:
            assert zf.testzip() is None  # No errors

    def test_zip_contains_handler(self):
        """Zip contains handler.py."""
        handler_code = build_script_handler("python")
        zip_bytes = build_deployment_zip(handler_code)

        buffer = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buffer, "r") as zf:
            assert "handler.py" in zf.namelist()

    def test_zip_handler_content_matches(self):
        """Handler content in zip matches the input."""
        handler_code = build_script_handler("shell")
        zip_bytes = build_deployment_zip(handler_code)

        buffer = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buffer, "r") as zf:
            content = zf.read("handler.py").decode("utf-8")
            assert content == handler_code
