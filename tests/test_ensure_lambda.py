"""ensure_lambda returns only when the function is Active."""

import pytest
from botocore.exceptions import ClientError

import cloud_run.aws_infra as aws_infra
from cloud_run.aws_infra import ensure_lambda

FUNCTION_ARN = "arn:aws:lambda:us-east-1:123456789012:function:fn"


class FakeLambda:
    def __init__(self, states: list[str], *, exists: bool = False):
        self._states = states
        self._cursor = 0
        self.exists = exists
        self.created = False
        self.seen: list[str] = []
        self.code_updates = 0
        self.config_updates = 0

    def get_function(self, FunctionName):
        if not self.exists and not self.created:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
                "GetFunction",
            )
        state = self._states[min(self._cursor, len(self._states) - 1)]
        self._cursor += 1
        self.seen.append(state)
        return {"Configuration": {"State": state, "FunctionArn": FUNCTION_ARN}}

    def create_function(self, **kwargs):
        self.created = True
        return {"FunctionArn": FUNCTION_ARN}

    def update_function_code(self, **kwargs):
        self.code_updates += 1
        return {}

    def update_function_configuration(self, **kwargs):
        self.config_updates += 1
        return {}


@pytest.fixture(autouse=True)
def fast_clock(monkeypatch):
    clock = {"now": 0.0}

    def now():
        return clock["now"]

    def sleep(seconds):
        clock["now"] += seconds

    monkeypatch.setattr(aws_infra.time, "time", now)
    monkeypatch.setattr(aws_infra.time, "sleep", sleep)
    return clock


def _install(monkeypatch, fake: FakeLambda) -> FakeLambda:
    monkeypatch.setattr(aws_infra.boto3, "client", lambda *args, **kwargs: fake)
    return fake


def _ensure():
    return ensure_lambda(
        function_name="fn",
        role_arn="arn:aws:iam::123456789012:role/role",
        zip_bytes=b"zip",
        region_name="us-east-1",
    )


def test_create_returns_only_after_the_function_is_active(monkeypatch):
    fake = _install(monkeypatch, FakeLambda(["Pending", "Active"]))

    arn = _ensure()

    assert arn == FUNCTION_ARN
    assert fake.created
    assert fake.seen == ["Pending", "Active"]
    assert fake.config_updates == 0


def test_create_raises_when_the_function_never_becomes_active(monkeypatch):
    fake = _install(monkeypatch, FakeLambda(["Pending"]))

    with pytest.raises(RuntimeError, match="did not become Active"):
        _ensure()

    assert fake.created
    assert set(fake.seen) == {"Pending"}


def test_create_raises_when_the_function_fails(monkeypatch):
    fake = _install(monkeypatch, FakeLambda(["Failed"]))

    with pytest.raises(RuntimeError, match="Failed state"):
        _ensure()

    assert fake.created


def test_update_returns_only_after_configuration_is_active(monkeypatch):
    fake = _install(
        monkeypatch,
        FakeLambda(["Active", "Pending", "Active", "Pending", "Active"], exists=True),
    )

    arn = _ensure()

    assert arn == FUNCTION_ARN
    assert fake.code_updates == 1
    assert fake.config_updates == 1
    assert fake.seen == ["Active", "Pending", "Active", "Pending", "Active"]


def test_update_does_not_change_configuration_when_the_code_update_fails(monkeypatch):
    fake = _install(monkeypatch, FakeLambda(["Active", "Failed"], exists=True))

    with pytest.raises(RuntimeError, match="Failed state"):
        _ensure()

    assert fake.code_updates == 1
    assert fake.config_updates == 0


def test_update_raises_when_the_function_fails_after_configuration(monkeypatch):
    fake = _install(monkeypatch, FakeLambda(["Active", "Active", "Failed"], exists=True))

    with pytest.raises(RuntimeError, match="Failed state"):
        _ensure()

    assert fake.config_updates == 1


def test_configuration_update_retries_a_conflict(monkeypatch):
    class ConflictLambda(FakeLambda):
        def update_function_configuration(self, **kwargs):
            self.config_updates += 1
            if self.config_updates == 1:
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ResourceConflictException",
                            "Message": "update in progress",
                        }
                    },
                    "UpdateFunctionConfiguration",
                )

    fake = _install(monkeypatch, ConflictLambda(["Active"], exists=True))

    arn = _ensure()

    assert arn == FUNCTION_ARN
    assert fake.code_updates == 1
    assert fake.config_updates == 2
