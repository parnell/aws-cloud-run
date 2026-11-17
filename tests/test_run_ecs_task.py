"""The ECS override is the contract of run_ecs_task."""

import json
import subprocess

import pytest
from botocore.exceptions import ClientError

import cloud_run.ecs_infra as ecs_infra
from cloud_run.ecs_infra import run_ecs_task

TASK_ARN = "arn:aws:ecs:us-east-1:123456789012:task/cluster/abc"
CLUSTER_ARN = "arn:aws:ecs:us-east-1:123456789012:cluster/c"
TASK_DEFINITION_ARN = "arn:aws:ecs:us-east-1:123456789012:task-definition/fam:1"


class FakeECS:
    def __init__(self):
        self.kwargs = None

    def run_task(self, **kwargs):
        self.kwargs = kwargs
        return {"tasks": [{"taskArn": TASK_ARN}]}


class FakeSecrets:
    def __init__(self, secrets: dict[str, str]):
        self.secrets = secrets

    def get_secret_value(self, SecretId):
        if SecretId not in self.secrets:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "missing"}},
                "GetSecretValue",
            )
        return {"SecretString": self.secrets[SecretId]}


def _install(monkeypatch, secrets=None, ecs=None):
    ecs = ecs or FakeECS()
    sm = FakeSecrets(secrets or {})

    def client(service, **kwargs):
        if service == "ecs":
            return ecs
        if service == "secretsmanager":
            return sm
        raise AssertionError(service)

    monkeypatch.setattr(ecs_infra.boto3, "client", client)
    return ecs


def _run(**kwargs):
    defaults = {
        "cluster_arn": CLUSTER_ARN,
        "task_definition_arn": TASK_DEFINITION_ARN,
        "subnet_ids": ["subnet-a"],
        "script_content": "print('hi')",
        "region_name": "us-east-1",
    }
    defaults.update(kwargs)
    return run_ecs_task(**defaults)


def _override(ecs):
    overrides = ecs.kwargs["overrides"]["containerOverrides"]
    assert len(overrides) == 1
    return overrides[0]


def test_python_override_runs_the_script_with_args(monkeypatch):
    ecs = _install(monkeypatch)

    arn = _run(
        script_content="import sys\nprint('|'.join(sys.argv))",
        script_type="python",
        script_args=["hello world", "again"],
        container_name="worker",
    )

    assert arn == TASK_ARN
    assert ecs.kwargs["cluster"] == CLUSTER_ARN
    assert ecs.kwargs["taskDefinition"] == TASK_DEFINITION_ARN
    assert ecs.kwargs["launchType"] == "FARGATE"
    override = _override(ecs)
    assert override["name"] == "worker"
    result = subprocess.run(override["command"], check=True, capture_output=True, text=True)
    assert result.stdout.strip() == "script|hello world|again"


def test_shell_comments_are_not_part_of_the_override(monkeypatch):
    commented = _install(monkeypatch)
    _run(
        script_content="#!/bin/bash\n# echo LEAKED_COMMENT\n\necho kept\n",
        script_type="shell",
    )
    commented_command = _override(commented)["command"]

    clean = _install(monkeypatch)
    _run(script_content="#!/bin/bash\necho kept\n", script_type="shell")
    clean_command = _override(clean)["command"]

    assert commented_command == clean_command
    result = subprocess.run(clean_command, check=True, capture_output=True, text=True)
    assert result.stdout.strip() == "kept"


def test_passed_subnets_and_security_groups_are_sent_unchanged(monkeypatch):
    ecs = _install(monkeypatch)

    _run(
        subnet_ids=["subnet-a", "subnet-b", "subnet-c", "subnet-d"],
        security_group_ids=["sg-1"],
        assign_public_ip="DISABLED",
    )

    network = ecs.kwargs["networkConfiguration"]["awsvpcConfiguration"]
    assert network["subnets"] == ["subnet-a", "subnet-b", "subnet-c", "subnet-d"]
    assert network["securityGroups"] == ["sg-1"]
    assert network["assignPublicIp"] == "DISABLED"
    assert _override(ecs)["name"] == "script-runner"


def test_secret_json_is_merged_into_the_environment(monkeypatch):
    ecs = _install(
        monkeypatch,
        secrets={"app/prod": json.dumps({"TOKEN": "s3cret", "N": 2})},
    )

    _run(env_vars={"PLAIN": "yes"}, secrets=["app/prod"])

    env = {item["name"]: item["value"] for item in _override(ecs)["environment"]}
    assert env == {"PLAIN": "yes", "TOKEN": "s3cret", "N": "2"}


def test_non_object_secret_is_left_out_of_the_environment(monkeypatch, capsys):
    ecs = _install(monkeypatch, secrets={"app/prod": json.dumps(["nope"])})

    _run(env_vars={"PLAIN": "yes"}, secrets=["app/prod"])

    env = {item["name"]: item["value"] for item in _override(ecs)["environment"]}
    assert env == {"PLAIN": "yes"}
    assert "not a JSON object" in capsys.readouterr().err


def test_missing_secret_raises_before_the_task_starts(monkeypatch):
    ecs = _install(monkeypatch, secrets={})

    with pytest.raises(RuntimeError, match="Failed to fetch secret 'missing'"):
        _run(secrets=["missing"])

    assert ecs.kwargs is None


def test_runtime_secret_is_named_in_the_command_not_the_environment(monkeypatch):
    ecs = _install(monkeypatch)

    _run(script_content="print('hi')", runtime_secrets=["runtime/secret"])

    override = _override(ecs)
    assert "environment" not in override
    command = json.dumps(override["command"])
    assert "runtime/secret" in command
    assert "secretsmanager" in command


def test_oversized_override_warns_and_still_starts(monkeypatch, capsys):
    ecs = _install(monkeypatch)

    arn = _run(env_vars={"BIG": "x" * 9000})

    assert arn == TASK_ARN
    assert ecs.kwargs is not None
    err = capsys.readouterr().err
    assert "exceed ECS limit of 8192" in err
    assert "Attempting to run anyway" in err
    assert "--runtime-secret" in err


def test_run_task_with_no_tasks_raises(monkeypatch):
    class EmptyECS(FakeECS):
        def run_task(self, **kwargs):
            self.kwargs = kwargs
            return {"tasks": [], "failures": [{"reason": "boom"}]}

    _install(monkeypatch, ecs=EmptyECS())

    with pytest.raises(RuntimeError, match="boom"):
        _run()
