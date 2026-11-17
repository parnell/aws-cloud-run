"""CLI listings for VPCs, ECS tasks, and task definitions.

Cluster task-definition hints used while launching a script stay on the launch path.
"""

import sys

import boto3


def list_vpcs(region: str) -> None:
    """List available VPCs and their subnets with internet connectivity info."""
    ec2 = boto3.client("ec2", region_name=region)

    try:
        vpcs = ec2.describe_vpcs()
    except Exception as e:
        print(f"Error listing VPCs: {e}", file=sys.stderr)
        return

    if not vpcs.get("Vpcs"):
        print(f"No VPCs found in {region}")
        return

    # Get all route tables to check internet access
    route_tables = ec2.describe_route_tables()["RouteTables"]

    # Build map of subnet -> has internet access
    subnet_internet = {}
    for rt in route_tables:
        has_igw = any(
            r.get("GatewayId", "").startswith("igw-")
            for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        )
        has_nat = any(
            r.get("NatGatewayId", "").startswith("nat-")
            for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        )

        internet_type = None
        if has_igw:
            internet_type = "IGW"
        elif has_nat:
            internet_type = "NAT"

        # Check explicit subnet associations
        for assoc in rt.get("Associations", []):
            subnet_id = assoc.get("SubnetId")
            if subnet_id and internet_type:
                subnet_internet[subnet_id] = internet_type

        # Check if this is a main route table (default for VPC)
        for assoc in rt.get("Associations", []):
            if assoc.get("Main") and internet_type:
                vpc_id = rt.get("VpcId")
                subnet_internet[f"main:{vpc_id}"] = internet_type

    print(f"VPCs and Subnets in {region}:\n")
    print("Legend: internet=IGW (Internet Gateway), NAT (NAT Gateway), ✗ (no internet)")
    print()

    for vpc in vpcs["Vpcs"]:
        vpc_id = vpc["VpcId"]
        is_default = vpc.get("IsDefault", False)
        cidr = vpc.get("CidrBlock", "-")

        # Get VPC name from tags
        vpc_name = "-"
        for tag in vpc.get("Tags", []):
            if tag["Key"] == "Name":
                vpc_name = tag["Value"]
                break

        default_marker = " (default)" if is_default else ""
        print(f"━━━ VPC: {vpc_id}{default_marker} ━━━")
        print(f"    Name: {vpc_name}")
        print(f"    CIDR: {cidr}")
        print("    Subnets:")

        # Get subnets
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

        if not subnets["Subnets"]:
            print("      (none)")
        else:
            for subnet in subnets["Subnets"]:
                subnet_id = subnet["SubnetId"]
                az = subnet.get("AvailabilityZone", "-")
                public_ip = "✓" if subnet.get("MapPublicIpOnLaunch") else "✗"

                # Check internet access
                internet = (
                    subnet_internet.get(subnet_id) or subnet_internet.get(f"main:{vpc_id}") or "✗"
                )

                # Get subnet name
                subnet_name = "-"
                for tag in subnet.get("Tags", []):
                    if tag["Key"] == "Name":
                        subnet_name = tag["Value"]
                        break

                print(
                    f"      {subnet_id}  {az}  public:{public_ip}  internet:{internet}  {subnet_name}"
                )

        print()

    print("Usage: cloud_run script.py --ecs --subnets <subnet-with-NAT-or-IGW>")
    print("       (Use subnets with internet:NAT or internet:IGW for Fargate)")
    print()
    print("Tip: For Fargate, use subnets with internet:NAT (private) or internet:IGW + public:✓")


def list_ecs_tasks(region: str) -> None:
    """List recent ECS tasks from all clusters."""
    ecs = boto3.client("ecs", region_name=region)

    # List all clusters
    try:
        cluster_arns = ecs.list_clusters().get("clusterArns", [])
    except Exception as e:
        print(f"Error listing clusters: {e}", file=sys.stderr)
        return

    if not cluster_arns:
        print(f"No ECS clusters found in {region}")
        return

    # Get cluster details
    clusters_response = ecs.describe_clusters(clusters=cluster_arns)
    clusters = [c for c in clusters_response.get("clusters", []) if c["status"] == "ACTIVE"]

    if not clusters:
        print(f"No active ECS clusters found in {region}")
        return

    print(f"ECS Tasks in {region}:\n")

    total_tasks = 0

    for cluster in clusters:
        cluster_name = cluster.get("clusterName", "unknown")
        cluster_arn = cluster.get("clusterArn", "")

        # List running and stopped tasks
        running = ecs.list_tasks(cluster=cluster_arn, desiredStatus="RUNNING")
        stopped = ecs.list_tasks(cluster=cluster_arn, desiredStatus="STOPPED")

        all_task_arns = running.get("taskArns", []) + stopped.get("taskArns", [])

        if not all_task_arns:
            continue

        # Get task details
        tasks_response = ecs.describe_tasks(cluster=cluster_arn, tasks=all_task_arns[:20])
        tasks = tasks_response.get("tasks", [])

        if not tasks:
            continue

        # Sort by created time (newest first)
        tasks.sort(key=lambda t: t.get("createdAt", ""), reverse=True)

        # Print cluster header
        print(f"━━━ Cluster: {cluster_name} ━━━")
        print(f"{'Status':<12} {'Task ID':<38} {'Exit':<6} {'Created':<20} {'Task Definition'}")
        print("-" * 110)

        for task in tasks:
            task_arn = task.get("taskArn", "")
            task_id = task_arn.split("/")[-1] if task_arn else "unknown"
            status = task.get("lastStatus", "UNKNOWN")

            # Get exit code from container
            containers = task.get("containers", [])
            exit_code = "-"
            if containers and "exitCode" in containers[0]:
                exit_code = str(containers[0]["exitCode"])

            # Format created time
            created = task.get("createdAt")
            if created:
                created_str = created.strftime("%Y-%m-%d %H:%M:%S")
            else:
                created_str = "-"

            # Get task definition name
            task_def = task.get("taskDefinitionArn", "").split("/")[-1]

            # Color status
            if status == "RUNNING":
                status_display = f"\033[33m{status:<12}\033[0m"  # Yellow
            elif status == "STOPPED" and exit_code == "0":
                status_display = f"\033[32m{status:<12}\033[0m"  # Green
            elif status == "STOPPED":
                status_display = f"\033[31m{status:<12}\033[0m"  # Red
            else:
                status_display = f"{status:<12}"

            print(f"{status_display} {task_id:<38} {exit_code:<6} {created_str:<20} {task_def}")

        total_tasks += len(tasks)
        print()

    if total_tasks == 0:
        print("No tasks found in any cluster.")
    else:
        print(f"Total: {total_tasks} tasks shown across {len(clusters)} cluster(s)")


def list_task_definitions(region: str, prefix: str | None = None) -> None:
    """List available ECS task definitions, optionally filtered by prefix."""
    ecs = boto3.client("ecs", region_name=region)

    try:
        # List task definition families
        families = []
        paginator = ecs.get_paginator("list_task_definition_families")
        # Use familyPrefix if provided
        paginate_kwargs = {"status": "ACTIVE"}
        if prefix:
            paginate_kwargs["familyPrefix"] = prefix
        for page in paginator.paginate(**paginate_kwargs):
            families.extend(page.get("families", []))
    except Exception as e:
        print(f"Error listing task definitions: {e}", file=sys.stderr)
        return

    if not families:
        if prefix:
            print(f"No task definitions found matching '{prefix}*' in {region}")
        else:
            print(f"No task definitions found in {region}")
        return

    # Header
    if prefix:
        print(f"\nECS Task Definitions matching '{prefix}*' in {region}:\n")
    else:
        print(f"\nECS Task Definitions in {region}:\n")

    print(f"{'Family':<50} {'Rev':<6} {'CPU':<6} {'Mem':<6} {'Containers':<12} {'Image'}")
    print("-" * 120)

    for family in sorted(families):
        try:
            # Get latest revision
            response = ecs.describe_task_definition(taskDefinition=family)
            task_def = response.get("taskDefinition", {})

            revision = str(task_def.get("revision", "-"))
            cpu = task_def.get("cpu", "-")
            memory = task_def.get("memory", "-")

            # Get container info
            containers = task_def.get("containerDefinitions", [])
            container_count = str(len(containers))
            image = containers[0].get("image", "-") if containers else "-"

            # Truncate long image names
            if len(image) > 35:
                image = "..." + image[-32:]

            # Color code based on container count
            if len(containers) == 1:
                status = f"{Colors.GREEN}✓{Colors.RESET}"
            else:
                status = f"{Colors.YELLOW}⚠{Colors.RESET}"

            print(
                f"{status} {family:<48} {revision:<6} {cpu:<6} {memory:<6} {container_count:<12} {image}"
            )
        except Exception:
            print(f"  {family:<48} (error fetching details)")

    print(f"\nTotal: {len(families)} task definition families")
    if prefix:
        print("\nUsage: cloud_run script.py --ecs --cluster <cluster> --task-definition <family>")
    else:
        print(
            "\nTip: Use --list-task-definitions <prefix> to filter (e.g., --list-task-definitions scaffold-dev-)"
        )


# ANSI color codes
class Colors:
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
