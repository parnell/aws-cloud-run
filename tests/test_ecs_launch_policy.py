"""Launch-policy tests: VPC failures, the subnet cap, and task-definition listing."""

import boto3
import botocore.exceptions as botocore_exceptions
import pytest
from moto import mock_aws

import cloud_run.ecs_runner as ecs_runner
from cloud_run.lib.ecs_utils import list_cluster_task_definitions


def _active_cluster():
    return {
        "clusters": [
            {
                "clusterArn": "arn:aws:ecs:us-east-2:123:cluster/my-cluster",
                "status": "ACTIVE",
            }
        ]
    }


def test_resolve_ecs_config_caps_explicit_subnets_at_three(monkeypatch):
    class FakeECS:
        def describe_clusters(self, clusters):
            return _active_cluster()

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeECS())

    config = ecs_runner._resolve_ecs_config(
        region="us-east-2",
        cluster_name="my-cluster",
        task_definition="my-family",
        vpc_name_or_id=None,
        subnet_ids=["subnet-a", "subnet-b", "subnet-c", "subnet-d"],
        security_group_ids=None,
        cpu="256",
        memory="512",
        script_type="shell",
        create_cluster=False,
        container_name="my-container",
    )

    assert config.subnet_ids == ["subnet-a", "subnet-b", "subnet-c"]


def test_resolve_ecs_config_missing_vpc_raises(monkeypatch):
    class FakeECS:
        def describe_clusters(self, clusters):
            return _active_cluster()

    class FakeEC2:
        def describe_vpcs(self, Filters):
            return {"Vpcs": []}

    def client(service, **kwargs):
        if service == "ec2":
            return FakeEC2()
        return FakeECS()

    monkeypatch.setattr(ecs_runner.boto3, "client", client)

    with pytest.raises(RuntimeError, match="not found"):
        ecs_runner._resolve_ecs_config(
            region="us-east-2",
            cluster_name="my-cluster",
            task_definition="my-family",
            vpc_name_or_id="missing",
            subnet_ids=None,
            security_group_ids=None,
            cpu="256",
            memory="512",
            script_type="shell",
            create_cluster=False,
            container_name="my-container",
        )


@mock_aws
def test_resolve_vpc_returns_every_public_subnet():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.3.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "app"}])

    public_ids = []
    for index, cidr in enumerate(("10.3.1.0/24", "10.3.2.0/24", "10.3.3.0/24", "10.3.4.0/24")):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr)["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": f"public-{index}"}])
        public_ids.append(subnet_id)

    private_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.3.5.0/24")["Subnet"]["SubnetId"]
    ec2.create_tags(Resources=[private_id], Tags=[{"Key": "Name", "Value": "internal"}])

    result = ecs_runner.resolve_vpc_and_subnets("us-east-1", "app", None)

    assert set(result) == set(public_ids)
    assert private_id not in result


@mock_aws
def test_resolve_vpc_missing_name_raises():
    with pytest.raises(RuntimeError, match="not found"):
        ecs_runner.resolve_vpc_and_subnets("us-east-1", "missing", None)


@mock_aws
def test_resolve_vpc_ambiguous_name_raises():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    for cidr in ("10.1.0.0/16", "10.2.0.0/16"):
        vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "shared"}])

    with pytest.raises(RuntimeError, match="Multiple VPCs"):
        ecs_runner.resolve_vpc_and_subnets("us-east-1", "shared", None)


@mock_aws
def test_resolve_vpc_without_subnets_raises():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.4.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "empty"}])

    with pytest.raises(RuntimeError, match="No subnets found"):
        ecs_runner.resolve_vpc_and_subnets("us-east-1", "empty", None)


def test_resolve_vpc_missing_credentials_prompts_sso_login(monkeypatch):
    class FakeEC2:
        def describe_vpcs(self, Filters):
            raise botocore_exceptions.NoCredentialsError()

    monkeypatch.setattr(ecs_runner.boto3, "client", lambda *args, **kwargs: FakeEC2())

    with pytest.raises(RuntimeError, match="aws sso login"):
        ecs_runner.resolve_vpc_and_subnets("us-east-1", "app", None)


def test_list_cluster_task_definitions_raises_on_missing_credentials():
    class FakeECS:
        def list_tasks(self, **kwargs):
            raise botocore_exceptions.NoCredentialsError()

    with pytest.raises(RuntimeError, match="aws sso login"):
        list_cluster_task_definitions(
            FakeECS(),
            "arn:aws:ecs:us-east-2:123:cluster/my-cluster",
            "us-east-2",
        )


def test_list_cluster_task_definitions_raises_when_listing_fails():
    class FakeECS:
        def list_tasks(self, **kwargs):
            raise botocore_exceptions.ClientError(
                {"Error": {"Code": "ClusterNotFoundException", "Message": "cluster missing"}},
                "ListTasks",
            )

    with pytest.raises(RuntimeError, match="Failed to list task definitions"):
        list_cluster_task_definitions(
            FakeECS(),
            "arn:aws:ecs:us-east-2:123:cluster/my-cluster",
            "us-east-2",
        )


def test_list_cluster_task_definitions_skips_one_unreadable_family():
    class FakeECS:
        def list_tasks(self, **kwargs):
            return {"taskArns": ["arn:aws:ecs:us-east-2:123:task/my-cluster/a"]}

        def describe_tasks(self, **kwargs):
            return {
                "tasks": [
                    {
                        "taskDefinitionArn": "arn:aws:ecs:us-east-2:123:task-definition/good:1",
                        "lastStatus": "RUNNING",
                    },
                    {
                        "taskDefinitionArn": "arn:aws:ecs:us-east-2:123:task-definition/bad:1",
                        "lastStatus": "STOPPED",
                    },
                ]
            }

        def describe_task_definition(self, taskDefinition):
            if taskDefinition.endswith("bad:1"):
                raise botocore_exceptions.ClientError(
                    {"Error": {"Code": "ClientException", "Message": "unable to describe"}},
                    "DescribeTaskDefinition",
                )
            return {
                "taskDefinition": {
                    "containerDefinitions": [{"name": "main", "image": "nginx:latest"}]
                }
            }

    results = list_cluster_task_definitions(
        FakeECS(),
        "arn:aws:ecs:us-east-2:123:cluster/my-cluster",
        "us-east-2",
    )

    assert [item["family"] for item in results] == ["good"]


def test_list_cluster_task_definitions_raises_when_describe_loses_credentials():
    class FakeECS:
        def list_tasks(self, **kwargs):
            return {"taskArns": ["arn:aws:ecs:us-east-2:123:task/my-cluster/a"]}

        def describe_tasks(self, **kwargs):
            return {
                "tasks": [
                    {
                        "taskDefinitionArn": "arn:aws:ecs:us-east-2:123:task-definition/good:1",
                        "lastStatus": "RUNNING",
                    }
                ]
            }

        def describe_task_definition(self, taskDefinition):
            raise botocore_exceptions.NoCredentialsError()

    with pytest.raises(RuntimeError, match="aws sso login"):
        list_cluster_task_definitions(
            FakeECS(),
            "arn:aws:ecs:us-east-2:123:cluster/my-cluster",
            "us-east-2",
        )
