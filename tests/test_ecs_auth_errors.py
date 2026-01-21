import botocore.exceptions as botocore_exceptions
import pytest

import cloud_run.ecs_runner as ecs_runner


def test_ecs_cluster_lookup_prompts_sso_login_on_no_credentials(monkeypatch):
    class FakeECS:
        def describe_clusters(self, clusters):
            raise botocore_exceptions.NoCredentialsError()

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeECS())

    with pytest.raises(RuntimeError) as exc:
        ecs_runner._resolve_ecs_config(
            region="us-east-2",
            cluster_name="scaffold-prod-ecs-cluster",
            task_definition=None,
            vpc_name_or_id=None,
            subnet_ids=["subnet-123"],
            security_group_ids=None,
            cpu="256",
            memory="512",
            script_type="shell",
            create_cluster=False,
        )

    assert "aws sso login" in str(exc.value).lower()


def test_ecs_cluster_lookup_prompts_sso_login_on_expired_token(monkeypatch):
    class FakeECS:
        def describe_clusters(self, clusters):
            raise botocore_exceptions.ClientError(
                {
                    "Error": {
                        "Code": "ExpiredTokenException",
                        "Message": "The security token included in the request is expired",
                    }
                },
                "DescribeClusters",
            )

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeECS())

    with pytest.raises(RuntimeError) as exc:
        ecs_runner._resolve_ecs_config(
            region="us-east-2",
            cluster_name="scaffold-prod-ecs-cluster",
            task_definition=None,
            vpc_name_or_id=None,
            subnet_ids=["subnet-123"],
            security_group_ids=None,
            cpu="256",
            memory="512",
            script_type="shell",
            create_cluster=False,
        )

    assert "aws sso login" in str(exc.value).lower()


def test_ecs_cluster_not_found_message_unchanged(monkeypatch):
    class FakeECS:
        def describe_clusters(self, clusters):
            return {"clusters": [], "failures": [{"arn": clusters[0], "reason": "MISSING"}]}

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeECS())

    with pytest.raises(RuntimeError) as exc:
        ecs_runner._resolve_ecs_config(
            region="us-east-2",
            cluster_name="scaffold-prod-ecs-cluster",
            task_definition=None,
            vpc_name_or_id=None,
            subnet_ids=["subnet-123"],
            security_group_ids=None,
            cpu="256",
            memory="512",
            script_type="shell",
            create_cluster=False,
        )

    assert "cluster 'scaffold-prod-ecs-cluster' not found" in str(exc.value).lower()
