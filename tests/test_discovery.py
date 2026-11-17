"""The --list-* commands are a listing module, separate from an ECS script run."""

import boto3
from moto import mock_aws

from cloud_run.discovery import list_ecs_tasks, list_task_definitions, list_vpcs
from cloud_run.ecs_infra import ensure_ecs_execution_role, register_task_definition


@mock_aws
def test_list_vpcs_prints_the_named_vpc_and_subnet(capsys):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.8.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "app-vpc"}])
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.8.1.0/24")["Subnet"]["SubnetId"]

    list_vpcs("us-east-1")

    out = capsys.readouterr().out
    assert vpc_id in out
    assert "app-vpc" in out
    assert subnet_id in out


@mock_aws
def test_list_ecs_tasks_reports_when_the_region_has_no_clusters(capsys):
    list_ecs_tasks("us-east-1")

    assert "No ECS clusters found" in capsys.readouterr().out


@mock_aws
def test_list_task_definitions_prints_a_registered_family(capsys):
    role_arn = ensure_ecs_execution_role(region_name="us-east-1")
    register_task_definition(
        family="listed-family",
        execution_role_arn=role_arn,
        script_type="python",
        region_name="us-east-1",
    )

    list_task_definitions("us-east-1", prefix="listed-")

    assert "listed-family" in capsys.readouterr().out


@mock_aws
def test_list_task_definitions_says_when_the_prefix_matches_nothing(capsys):
    list_task_definitions("us-east-1", prefix="no-such-family")

    assert "No task definitions found matching 'no-such-family*'" in capsys.readouterr().out
