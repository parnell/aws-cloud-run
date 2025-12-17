"""Tests for CLI utilities."""

from pathlib import Path

from cloud_run.cli import _detect_script_type


class TestDetectScriptType:
    """Tests for script type detection."""

    def test_python_extension(self):
        """Files with .py extension are detected as Python."""
        assert _detect_script_type(Path("script.py"), "") == "python"
        assert _detect_script_type(Path("my_script.py"), "# some content") == "python"
        assert _detect_script_type(Path("/path/to/script.py"), "") == "python"

    def test_shell_extensions(self):
        """Files with .sh or .bash extensions are detected as shell."""
        assert _detect_script_type(Path("script.sh"), "") == "shell"
        assert _detect_script_type(Path("script.bash"), "") == "shell"
        assert _detect_script_type(Path("/path/to/run.sh"), "") == "shell"

    def test_python_shebang(self):
        """Files with Python shebang are detected as Python."""
        assert (
            _detect_script_type(Path("script"), "#!/usr/bin/env python3\nprint('hi')") == "python"
        )
        assert _detect_script_type(Path("script"), "#!/usr/bin/python\nimport sys") == "python"
        assert _detect_script_type(Path("script"), "#! /usr/bin/env python\ncode") == "python"

    def test_shell_shebang(self):
        """Files with shell shebang are detected as shell."""
        assert _detect_script_type(Path("script"), "#!/bin/bash\necho hi") == "shell"
        assert _detect_script_type(Path("script"), "#!/bin/sh\necho hi") == "shell"
        assert _detect_script_type(Path("script"), "#!/usr/bin/env zsh\necho hi") == "shell"
        assert _detect_script_type(Path("script"), "#!/usr/bin/env fish\necho hi") == "shell"

    def test_extension_takes_precedence_over_shebang(self):
        """File extension is checked before shebang."""
        # .py file with bash shebang should still be Python
        assert _detect_script_type(Path("script.py"), "#!/bin/bash\necho hi") == "python"
        # .sh file with Python shebang should still be shell
        assert _detect_script_type(Path("script.sh"), "#!/usr/bin/python\nprint('hi')") == "shell"

    def test_no_extension_no_shebang_defaults_to_shell(self):
        """Files without extension or shebang default to shell."""
        assert _detect_script_type(Path("script"), "some content") == "shell"
        assert _detect_script_type(Path("script"), "") == "shell"

    def test_case_insensitive_extension(self):
        """Extension detection is case-insensitive."""
        assert _detect_script_type(Path("script.PY"), "") == "python"
        assert _detect_script_type(Path("script.Py"), "") == "python"
        assert _detect_script_type(Path("script.SH"), "") == "shell"
        assert _detect_script_type(Path("script.BASH"), "") == "shell"
