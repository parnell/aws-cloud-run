"""Tests for ECS infrastructure functions."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from cloud_run.ecs_infra import (
    ensure_ecs_cluster,
    ensure_ecs_execution_role,
    ensure_log_group,
    get_vpc_subnets,
    register_task_definition,
)


@mock_aws
def test_ensure_ecs_execution_role_creates_role():
    """ensure_ecs_execution_role creates a new role if it doesn't exist."""
    role_arn = ensure_ecs_execution_role(
        role_name="test-ecs-execution-role", region_name="us-east-1"
    )

    assert role_arn.startswith("arn:aws:iam::")
    assert "test-ecs-execution-role" in role_arn

    # Verify role exists
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.get_role(RoleName="test-ecs-execution-role")
    assert role["Role"]["RoleName"] == "test-ecs-execution-role"


@mock_aws
def test_ensure_ecs_execution_role_is_idempotent():
    """ensure_ecs_execution_role returns existing role if it exists."""
    # Create role first time
    arn1 = ensure_ecs_execution_role(role_name="test-ecs-role", region_name="us-east-1")

    # Call again - should return same role
    arn2 = ensure_ecs_execution_role(role_name="test-ecs-role", region_name="us-east-1")

    assert arn1 == arn2


@mock_aws
def test_ensure_ecs_cluster_creates_cluster():
    """ensure_ecs_cluster creates a new cluster if it doesn't exist."""
    cluster_arn = ensure_ecs_cluster(cluster_name="test-cluster", region_name="us-east-1")

    assert "test-cluster" in cluster_arn

    # Verify cluster exists
    ecs = boto3.client("ecs", region_name="us-east-1")
    response = ecs.describe_clusters(clusters=["test-cluster"])
    assert len(response["clusters"]) == 1
    assert response["clusters"][0]["clusterName"] == "test-cluster"


@mock_aws
def test_ensure_ecs_cluster_is_idempotent():
    """ensure_ecs_cluster returns existing cluster if it exists."""
    # Create cluster first time
    arn1 = ensure_ecs_cluster(cluster_name="my-cluster", region_name="us-east-1")

    # Call again - should return same cluster
    arn2 = ensure_ecs_cluster(cluster_name="my-cluster", region_name="us-east-1")

    assert arn1 == arn2


@mock_aws
def test_ensure_log_group_creates_log_group():
    """ensure_log_group creates a new log group."""
    ensure_log_group("/ecs/test-task", region_name="us-east-1")

    # Verify log group exists
    logs = boto3.client("logs", region_name="us-east-1")
    response = logs.describe_log_groups(logGroupNamePrefix="/ecs/test-task")
    assert len(response["logGroups"]) == 1


@mock_aws
def test_ensure_log_group_is_idempotent():
    """ensure_log_group doesn't error if log group exists."""
    # Create twice - should not raise
    ensure_log_group("/ecs/test-logs", region_name="us-east-1")
    ensure_log_group("/ecs/test-logs", region_name="us-east-1")


@mock_aws
def test_register_task_definition_python():
    """register_task_definition creates task definition for Python scripts."""
    # First create the execution role
    role_arn = ensure_ecs_execution_role(region_name="us-east-1")

    task_def_arn = register_task_definition(
        family="test-python-task",
        execution_role_arn=role_arn,
        script_type="python",
        cpu="256",
        memory="512",
        region_name="us-east-1",
    )

    assert "test-python-task" in task_def_arn

    # Verify task definition
    ecs = boto3.client("ecs", region_name="us-east-1")
    response = ecs.describe_task_definition(taskDefinition="test-python-task")
    task_def = response["taskDefinition"]

    assert task_def["cpu"] == "256"
    assert task_def["memory"] == "512"
    assert task_def["networkMode"] == "awsvpc"
    assert "FARGATE" in task_def["requiresCompatibilities"]


@mock_aws
def test_register_task_definition_shell():
    """register_task_definition creates task definition for shell scripts."""
    role_arn = ensure_ecs_execution_role(region_name="us-east-1")

    task_def_arn = register_task_definition(
        family="test-shell-task",
        execution_role_arn=role_arn,
        script_type="shell",
        cpu="512",
        memory="1024",
        region_name="us-east-1",
    )

    assert "test-shell-task" in task_def_arn

    # Verify container uses amazonlinux for shell
    ecs = boto3.client("ecs", region_name="us-east-1")
    response = ecs.describe_task_definition(taskDefinition="test-shell-task")
    containers = response["taskDefinition"]["containerDefinitions"]
    assert len(containers) == 1
    assert "amazonlinux" in containers[0]["image"]


@mock_aws
def test_get_vpc_subnets_with_explicit_subnets():
    """get_vpc_subnets uses explicitly provided subnet IDs."""
    # Create VPC and subnet
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    subnet_id = subnet["Subnet"]["SubnetId"]

    result_vpc, result_subnets = get_vpc_subnets(
        region_name="us-east-1",
        subnet_ids=[subnet_id],
    )

    assert result_subnets == [subnet_id]
    assert result_vpc == vpc_id


@mock_aws
def test_get_vpc_subnets_with_explicit_vpc():
    """get_vpc_subnets finds subnets in specified VPC."""
    # Create VPC with subnets
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    subnet2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.2.0/24")

    result_vpc, result_subnets = get_vpc_subnets(
        region_name="us-east-1",
        vpc_id=vpc_id,
    )

    assert result_vpc == vpc_id
    assert len(result_subnets) == 2
    assert subnet1["Subnet"]["SubnetId"] in result_subnets
    assert subnet2["Subnet"]["SubnetId"] in result_subnets


@mock_aws
def test_get_vpc_subnets_finds_default_vpc():
    """get_vpc_subnets finds default VPC when nothing specified."""
    # moto creates a default VPC automatically
    ec2 = boto3.resource("ec2", region_name="us-east-1")

    # Create default VPC if it doesn't exist
    client = boto3.client("ec2", region_name="us-east-1")
    vpcs = client.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])

    if not vpcs["Vpcs"]:
        # moto may need explicit creation
        vpc = ec2.create_vpc(CidrBlock="172.31.0.0/16")
        # Can't actually set isDefault in moto, so skip this test
        pytest.skip("moto doesn't support default VPC in this configuration")

    result_vpc, result_subnets = get_vpc_subnets(region_name="us-east-1")

    assert result_vpc is not None
    assert len(result_subnets) > 0
