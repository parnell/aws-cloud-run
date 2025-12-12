"""Tests for ECS utility functions."""

import pytest
from datetime import datetime, timezone, timedelta

from cloud_run.ecs_infra import _strip_shell_comments
from cloud_run.ecs_runner import _parse_ecr_image_uri, _human_readable_time


class TestStripShellComments:
    """Tests for shell comment stripping."""

    def test_preserves_shebang(self):
        """Shebang line is preserved."""
        script = "#!/bin/bash\n# comment\necho hi"
        result = _strip_shell_comments(script)
        assert result.startswith("#!/bin/bash")

    def test_removes_comment_lines(self):
        """Lines that are only comments are removed."""
        script = "#!/bin/bash\n# this is a comment\necho hi\n# another comment"
        result = _strip_shell_comments(script)
        assert "# this is a comment" not in result
        assert "# another comment" not in result
        assert "echo hi" in result

    def test_removes_blank_lines(self):
        """Blank lines are removed."""
        script = "#!/bin/bash\n\necho hi\n\n\necho bye"
        result = _strip_shell_comments(script)
        lines = result.split("\n")
        assert "" not in lines or lines == ["#!/bin/bash", "echo hi", "echo bye"]

    def test_preserves_inline_code(self):
        """Lines with code are preserved."""
        script = "#!/bin/bash\necho 'hello world'\nls -la"
        result = _strip_shell_comments(script)
        assert "echo 'hello world'" in result
        assert "ls -la" in result

    def test_empty_script(self):
        """Empty script returns empty string."""
        assert _strip_shell_comments("") == ""

    def test_only_shebang(self):
        """Script with only shebang returns just shebang."""
        script = "#!/bin/bash"
        result = _strip_shell_comments(script)
        assert result == "#!/bin/bash"


class TestParseECRImageUri:
    """Tests for ECR image URI parsing."""

    def test_standard_ecr_uri_with_tag(self):
        """Parse standard ECR URI with tag."""
        uri = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest"
        result = _parse_ecr_image_uri(uri)
        assert result is not None
        assert result["account"] == "123456789012"
        assert result["region"] == "us-east-1"
        assert result["repository"] == "my-repo"
        assert result["tag"] == "latest"
        assert result["digest"] is None

    def test_ecr_uri_with_digest(self):
        """Parse ECR URI with digest instead of tag."""
        uri = "123456789012.dkr.ecr.eu-west-1.amazonaws.com/app@sha256:abc123def456"
        result = _parse_ecr_image_uri(uri)
        assert result is not None
        assert result["account"] == "123456789012"
        assert result["region"] == "eu-west-1"
        assert result["repository"] == "app"
        assert result["digest"] == "sha256:abc123def456"

    def test_ecr_uri_no_tag_defaults_to_latest(self):
        """Parse ECR URI without tag defaults to 'latest'."""
        uri = "123456789012.dkr.ecr.us-west-2.amazonaws.com/myapp"
        result = _parse_ecr_image_uri(uri)
        assert result is not None
        assert result["tag"] == "latest"

    def test_ecr_uri_with_nested_repo(self):
        """Parse ECR URI with nested repository path."""
        uri = "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/team/project/app:v1.0"
        result = _parse_ecr_image_uri(uri)
        assert result is not None
        assert result["repository"] == "team/project/app"
        assert result["tag"] == "v1.0"

    def test_non_ecr_image_returns_none(self):
        """Non-ECR images return None."""
        assert _parse_ecr_image_uri("python:3.11") is None
        assert _parse_ecr_image_uri("nginx:latest") is None
        assert _parse_ecr_image_uri("public.ecr.aws/docker/library/python:3.12") is None
        assert _parse_ecr_image_uri("gcr.io/project/image:tag") is None

    def test_invalid_ecr_uri_returns_none(self):
        """Invalid ECR URIs return None."""
        assert _parse_ecr_image_uri("") is None
        assert _parse_ecr_image_uri("not-a-uri") is None


class TestHumanReadableTime:
    """Tests for human-readable time formatting."""

    def test_just_now(self):
        """Times less than a minute ago show 'just now'."""
        now = datetime.now(timezone.utc)
        result = _human_readable_time(now)
        assert result == "just now"

    def test_minutes_ago(self):
        """Times in the past few minutes show 'X minute(s) ago'."""
        now = datetime.now(timezone.utc)
        
        # 1 minute ago
        one_min_ago = now - timedelta(minutes=1)
        assert "minute" in _human_readable_time(one_min_ago)
        
        # 30 minutes ago
        thirty_min_ago = now - timedelta(minutes=30)
        result = _human_readable_time(thirty_min_ago)
        assert "minute" in result

    def test_hours_ago(self):
        """Times in the past few hours show 'X hour(s) ago'."""
        now = datetime.now(timezone.utc)
        
        # 1 hour ago
        one_hour_ago = now - timedelta(hours=1)
        assert "hour" in _human_readable_time(one_hour_ago)
        
        # 5 hours ago
        five_hours_ago = now - timedelta(hours=5)
        assert "hour" in _human_readable_time(five_hours_ago)

    def test_days_ago(self):
        """Times in the past few days show 'X day(s) ago'."""
        now = datetime.now(timezone.utc)
        
        # 2 days ago
        two_days_ago = now - timedelta(days=2)
        assert "day" in _human_readable_time(two_days_ago)

    def test_older_shows_date(self):
        """Times older than a week show the date."""
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=30)
        result = _human_readable_time(old)
        # Should be a date format like "2024-01-15"
        assert "-" in result

    def test_none_returns_unknown(self):
        """None input returns 'unknown'."""
        assert _human_readable_time(None) == "unknown"

    def test_handles_naive_datetime(self):
        """Handles datetime without timezone info."""
        # Create a naive datetime by removing timezone info from UTC time
        # This tests that the function handles naive datetimes gracefully
        aware_dt = datetime.now(timezone.utc) - timedelta(minutes=5)
        naive_dt = aware_dt.replace(tzinfo=None)
        result = _human_readable_time(naive_dt)
        assert "minute" in result

