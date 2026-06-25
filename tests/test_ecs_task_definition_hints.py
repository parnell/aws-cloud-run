"""Tests for ECS task definition resolution without DescribeTaskDefinition."""

import cloud_run.ecs_runner as ecs_runner
from cloud_run.lib.ecs_utils import extract_task_definition_family


class TestExtractTaskDefinitionFamily:
    def test_family_only(self):
        assert extract_task_definition_family("scaffold-prod-analyze-job") == (
            "scaffold-prod-analyze-job"
        )

    def test_family_with_revision(self):
        assert extract_task_definition_family("scaffold-prod-analyze-job:42") == (
            "scaffold-prod-analyze-job"
        )

    def test_arn(self):
        arn = "arn:aws:ecs:us-east-2:324037281424:task-definition/scaffold-prod-analyze-job:12"
        assert extract_task_definition_family(arn) == "scaffold-prod-analyze-job"


def test_resolve_ecs_config_skips_describe_with_container_name(monkeypatch):
    describe_called = False

    class FakeECS:
        def describe_clusters(self, clusters):
            return {
                "clusters": [
                    {
                        "clusterArn": "arn:aws:ecs:us-east-2:123:cluster/scaffold-prod-ecs-cluster",
                        "status": "ACTIVE",
                    }
                ]
            }

        def describe_task_definition(self, taskDefinition):
            nonlocal describe_called
            describe_called = True
            raise AssertionError("DescribeTaskDefinition should not be called")

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeECS())

    config = ecs_runner._resolve_ecs_config(
        region="us-east-2",
        cluster_name="scaffold-prod-ecs-cluster",
        task_definition="scaffold-prod-analyze-job",
        vpc_name_or_id=None,
        subnet_ids=["subnet-abc"],
        security_group_ids=["sg-123"],
        cpu="256",
        memory="512",
        script_type="shell",
        create_cluster=False,
        container_name="scaffold-prod-analyze-job",
        log_group="/scaffold/prod/app-log-group",
    )

    assert not describe_called
    assert config.task_def_arn == "scaffold-prod-analyze-job"
    assert config.task_family == "scaffold-prod-analyze-job"
    assert config.container_name == "scaffold-prod-analyze-job"
    assert config.log_group == "/scaffold/prod/app-log-group"
    assert config.subnet_ids == ["subnet-abc"]


def test_resolve_ecs_config_default_log_group_without_describe(monkeypatch):
    class FakeECS:
        def describe_clusters(self, clusters):
            return {
                "clusters": [
                    {
                        "clusterArn": "arn:aws:ecs:us-east-2:123:cluster/my-cluster",
                        "status": "ACTIVE",
                    }
                ]
            }

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeECS())

    config = ecs_runner._resolve_ecs_config(
        region="us-east-2",
        cluster_name="my-cluster",
        task_definition="my-family:3",
        vpc_name_or_id=None,
        subnet_ids=["subnet-abc"],
        security_group_ids=None,
        cpu="256",
        memory="512",
        script_type="shell",
        create_cluster=False,
        container_name="my-container",
    )

    assert config.log_group == "/ecs/my-family"


def test_resolve_ecs_config_still_describes_without_container_name(monkeypatch):
    describe_called = False

    class FakeECS:
        def describe_clusters(self, clusters):
            return {
                "clusters": [
                    {
                        "clusterArn": "arn:aws:ecs:us-east-2:123:cluster/my-cluster",
                        "status": "ACTIVE",
                    }
                ]
            }

        def describe_task_definition(self, taskDefinition):
            nonlocal describe_called
            describe_called = True
            return {
                "taskDefinition": {
                    "taskDefinitionArn": "arn:aws:ecs:us-east-2:123:task-definition/my-family:1",
                    "family": "my-family",
                    "containerDefinitions": [
                        {
                            "name": "my-container",
                            "image": "nginx:latest",
                            "logConfiguration": {
                                "logDriver": "awslogs",
                                "options": {"awslogs-group": "/ecs/my-family"},
                            },
                        }
                    ],
                }
            }

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeECS())
    monkeypatch.setattr(ecs_runner, "get_image_entrypoint", lambda *args, **kwargs: None)

    config = ecs_runner._resolve_ecs_config(
        region="us-east-2",
        cluster_name="my-cluster",
        task_definition="my-family",
        vpc_name_or_id=None,
        subnet_ids=["subnet-abc"],
        security_group_ids=None,
        cpu="256",
        memory="512",
        script_type="shell",
        create_cluster=False,
    )

    assert describe_called
    assert config.container_name == "my-container"
    assert config.log_group == "/ecs/my-family"
