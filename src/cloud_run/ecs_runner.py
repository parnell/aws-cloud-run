"""ECS Fargate execution utilities for cloud_run."""

import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

import boto3
from pydantic import BaseModel

from .ecs_infra import (
    ensure_ecs_cluster,
    ensure_ecs_execution_role,
    get_task_logs,
    register_task_definition,
    run_ecs_task,
    wait_for_task_completion,
)


class ECSConfig(BaseModel):
    """Configuration for running an ECS task."""
    
    region: str
    cluster_name: str
    cluster_arn: Optional[str] = None
    task_def_arn: Optional[str] = None
    task_family: Optional[str] = None
    container_name: Optional[str] = None
    log_group: Optional[str] = None
    subnet_ids: Optional[list[str]] = None
    security_group_ids: Optional[list[str]] = None
    cpu: str = "256"
    memory: str = "512"
    execution_role_arn: Optional[str] = None
    needs_new_task_def: bool = False


def resolve_vpc_and_subnets(
    region: str,
    vpc_name_or_id: str | None,
    subnet_ids: list[str] | None,
) -> list[str]:
    """Resolve VPC name/ID to subnet IDs.

    Returns list of subnet IDs to use.
    """
    ec2 = boto3.client("ec2", region_name=region)

    # If subnets explicitly provided, use them
    if subnet_ids:
        return subnet_ids

    # Need VPC to find subnets
    if not vpc_name_or_id:
        print("Error: --vpc or --subnets is required for ECS tasks.", file=sys.stderr)
        print("       Run 'cloud_run --list-vpcs' to see available VPCs.", file=sys.stderr)
        sys.exit(1)

    # Check if it's a VPC ID or name
    if vpc_name_or_id.startswith("vpc-"):
        vpc_id = vpc_name_or_id
    else:
        # Search by name tag
        vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "tag:Name", "Values": [vpc_name_or_id]}]
        )
        if not vpcs["Vpcs"]:
            print(f"Error: VPC '{vpc_name_or_id}' not found.", file=sys.stderr)
            print("       Run 'cloud_run --list-vpcs' to see available VPCs.", file=sys.stderr)
            sys.exit(1)
        if len(vpcs["Vpcs"]) > 1:
            print(f"Error: Multiple VPCs found with name '{vpc_name_or_id}':", file=sys.stderr)
            for vpc in vpcs["Vpcs"]:
                print(f"       - {vpc['VpcId']}", file=sys.stderr)
            print("       Please specify the VPC ID directly with --vpc vpc-xxx", file=sys.stderr)
            sys.exit(1)
        vpc_id = vpcs["Vpcs"][0]["VpcId"]

    print(f"[cloud_run] VPC: {vpc_id}", file=sys.stderr)

    # Get subnets - prefer public subnets first
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

    if not subnets["Subnets"]:
        print(f"Error: No subnets found in VPC {vpc_id}", file=sys.stderr)
        sys.exit(1)

    # Categorize subnets
    public_subnets = []
    private_subnets = []

    for subnet in subnets["Subnets"]:
        subnet_id = subnet["SubnetId"]
        # Check if it's a public subnet (by name convention or MapPublicIpOnLaunch)
        subnet_name = ""
        for tag in subnet.get("Tags", []):
            if tag["Key"] == "Name":
                subnet_name = tag["Value"].lower()
                break

        if subnet.get("MapPublicIpOnLaunch") or "public" in subnet_name:
            public_subnets.append(subnet_id)
        else:
            private_subnets.append(subnet_id)

    # Use public subnets if available, otherwise private
    # For Fargate with assignPublicIp=ENABLED, public subnets work best
    if public_subnets:
        selected = public_subnets[:3]  # Use up to 3 subnets for availability
        print(f"[cloud_run] Using {len(selected)} public subnet(s)", file=sys.stderr)
        return selected
    elif private_subnets:
        selected = private_subnets[:3]
        print(f"[cloud_run] Using {len(selected)} private subnet(s) (may need NAT gateway)", file=sys.stderr)
        return selected
    else:
        print(f"Error: No suitable subnets found in VPC {vpc_id}", file=sys.stderr)
        sys.exit(1)


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
                internet = subnet_internet.get(subnet_id) or subnet_internet.get(f"main:{vpc_id}") or "✗"

                # Get subnet name
                subnet_name = "-"
                for tag in subnet.get("Tags", []):
                    if tag["Key"] == "Name":
                        subnet_name = tag["Value"]
                        break

                print(f"      {subnet_id}  {az}  public:{public_ip}  internet:{internet}  {subnet_name}")

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


def list_task_definitions(region: str, prefix: Optional[str] = None) -> None:
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

            print(f"{status} {family:<48} {revision:<6} {cpu:<6} {memory:<6} {container_count:<12} {image}")
        except Exception:
            print(f"  {family:<48} (error fetching details)")

    print(f"\nTotal: {len(families)} task definition families")
    if prefix:
        print("\nUsage: cloud_run script.py --ecs --cluster <cluster> --task-definition <family>")
    else:
        print("\nTip: Use --list-task-definitions <prefix> to filter (e.g., --list-task-definitions scaffold-dev-)")


def _get_cluster_arn(ecs, cluster_name: str) -> Optional[str]:
    """Get cluster ARN if it exists, None otherwise."""
    try:
        response = ecs.describe_clusters(clusters=[cluster_name])
        active_clusters = [
            c for c in response.get("clusters", []) if c["status"] == "ACTIVE"
        ]
        if active_clusters:
            return active_clusters[0]["clusterArn"]
    except Exception:
        pass
    return None


def _parse_ecr_image_uri(image_uri: str) -> Optional[dict]:
    """Parse an ECR image URI into its components.
    
    Returns dict with registry, repository, tag/digest, or None if not an ECR image.
    """
    # ECR format: <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>
    # or: <account>.dkr.ecr.<region>.amazonaws.com/<repo>@sha256:<digest>
    ecr_pattern = r'^(\d+)\.dkr\.ecr\.([^.]+)\.amazonaws\.com/([^:@]+)(?::([^@]+)|@(.+))?$'
    match = re.match(ecr_pattern, image_uri)
    
    if not match:
        return None
    
    return {
        "account": match.group(1),
        "region": match.group(2),
        "repository": match.group(3),
        "tag": match.group(4) or "latest",
        "digest": match.group(5),
    }


def _get_image_entrypoint(image_uri: str, region: str) -> Optional[dict]:
    """Get the ENTRYPOINT from a Docker image in ECR.
    
    Returns dict with:
        - entrypoint: list or None
        - cmd: list or None  
        - safe: bool (True if entrypoint is safe for command override)
        - reason: str (explanation)
    
    Returns None if unable to inspect (non-ECR image, access denied, etc.)
    """
    parsed = _parse_ecr_image_uri(image_uri)
    if not parsed:
        # Not an ECR image (e.g., python:3.11 from Docker Hub)
        # We can't inspect it, but public images are usually safe
        return {
            "entrypoint": None,
            "cmd": None,
            "safe": True,
            "reason": "public image (cannot inspect, assuming safe)",
        }
    
    try:
        # Use the region from the image URI, not the task region
        ecr = boto3.client("ecr", region_name=parsed["region"])
        
        # Get the image manifest
        image_id = {"imageTag": parsed["tag"]} if parsed["tag"] else {"imageDigest": parsed["digest"]}
        
        response = ecr.batch_get_image(
            repositoryName=parsed["repository"],
            imageIds=[image_id],
            acceptedMediaTypes=["application/vnd.docker.distribution.manifest.v2+json"],
        )
        
        if not response.get("images"):
            return None
        
        manifest = json.loads(response["images"][0]["imageManifest"])
        config_digest = manifest.get("config", {}).get("digest")
        
        if not config_digest:
            return None
        
        # Get the image config blob
        blob_response = ecr.get_download_url_for_layer(
            repositoryName=parsed["repository"],
            layerDigest=config_digest,
        )
        
        # Download the config
        import urllib.request
        with urllib.request.urlopen(blob_response["downloadUrl"]) as resp:
            config = json.loads(resp.read().decode())
        
        # Extract entrypoint and cmd from config
        container_config = config.get("config", {})
        entrypoint = container_config.get("Entrypoint")
        cmd = container_config.get("Cmd")
        
        # Determine if it's safe for command override
        safe = True
        reason = ""
        
        if not entrypoint:
            safe = True
            reason = "no entrypoint"
        elif entrypoint in [["python"], ["python3"], ["/bin/sh", "-c"], ["/bin/bash", "-c"]]:
            safe = True
            reason = f"shell-style entrypoint: {entrypoint}"
        else:
            # Unknown entrypoint - could be safe if it uses exec "$@", but we can't tell
            safe = False
            reason = f"custom entrypoint: {entrypoint}"
        
        return {
            "entrypoint": entrypoint,
            "cmd": cmd,
            "safe": safe,
            "reason": reason,
        }
        
    except Exception as e:
        # Can't inspect - might be access denied, image doesn't exist, etc.
        return {
            "entrypoint": None,
            "cmd": None,
            "safe": None,  # Unknown
            "reason": f"could not inspect: {e}",
        }


def _list_cluster_task_definitions(ecs, cluster_arn: str, region: str) -> list[dict]:
    """List all unique task definitions from a cluster with their status and warnings.
    
    Returns list of dicts with:
        - family: task definition family name
        - task_def_arn: full ARN
        - status: 'running' or 'stopped'
        - service: service name if started by a service
        - containers: list of container names
        - container_count: number of containers
        - image: image URI (of first container)
        - warnings: list of warning strings
        - usable: True if safe to use without issues
    """
    try:
        # Get running and stopped tasks
        running = ecs.list_tasks(cluster=cluster_arn, desiredStatus="RUNNING", maxResults=20)
        stopped = ecs.list_tasks(cluster=cluster_arn, desiredStatus="STOPPED", maxResults=20)
        
        all_task_arns = running.get("taskArns", []) + stopped.get("taskArns", [])
        
        if not all_task_arns:
            return []
        
        # Get task details
        tasks_response = ecs.describe_tasks(cluster=cluster_arn, tasks=all_task_arns)
        tasks = tasks_response.get("tasks", [])
        
        # Group by task definition family and get unique ones
        seen_families = {}
        
        for task in tasks:
            task_def_arn = task.get("taskDefinitionArn")
            if not task_def_arn:
                continue
            
            # Extract family from ARN
            family = task_def_arn.split("/")[-1].rsplit(":", 1)[0]
            
            # Keep the most recent/relevant task for each family
            if family in seen_families:
                # Prefer running over stopped
                existing = seen_families[family]
                if existing["status"] == "running":
                    continue
            
            status = "running" if task.get("lastStatus") == "RUNNING" else "stopped"
            started_by = task.get("startedBy", "")
            service = None
            if started_by.startswith("ecs-svc/"):
                # Extract service name from group
                group = task.get("group", "")
                if group.startswith("service:"):
                    service = group[8:]
            
            seen_families[family] = {
                "task_def_arn": task_def_arn,
                "status": status,
                "service": service,
                "created_at": task.get("createdAt"),
            }
        
        # Now get full task definition details for each unique family
        results = []
        
        for family, task_info in seen_families.items():
            try:
                response = ecs.describe_task_definition(taskDefinition=task_info["task_def_arn"])
            except Exception:
                continue
            
            task_def = response.get("taskDefinition", {})
            containers = task_def.get("containerDefinitions", [])
            
            if not containers:
                continue
            
            container_names = [c.get("name", "?") for c in containers]
            first_container = containers[0]
            image = first_container.get("image", "")
            
            # Analyze warnings
            warnings = []
            usable = True
            
            # Check for multiple containers
            if len(containers) > 1:
                warnings.append(f"Has {len(containers)} containers (sidecars will also run): {container_names}")
                usable = False
            
            # Check for entrypoint override in task def
            entrypoint = first_container.get("entryPoint")
            if entrypoint:
                warnings.append(f"Has custom entryPoint: {entrypoint}")
                usable = False
            
            # Check image entrypoint
            if image:
                image_info = _get_image_entrypoint(image, region)
                if image_info and image_info.get("safe") is False:
                    warnings.append(f"Image {image_info.get('reason')}")
                    usable = False
            
            # Extract log group
            log_config = first_container.get("logConfiguration", {})
            log_group = None
            if log_config.get("logDriver") == "awslogs":
                log_group = log_config.get("options", {}).get("awslogs-group")
            if not log_group:
                log_group = f"/ecs/{family}"
            
            results.append({
                "family": family,
                "task_def_arn": task_info["task_def_arn"],
                "status": task_info["status"],
                "service": task_info["service"],
                "created_at": task_info["created_at"],
                "containers": container_names,
                "container_count": len(containers),
                "container_name": container_names[0],
                "image": image,
                "log_group": log_group,
                "warnings": warnings,
                "usable": usable,
            })
        
        # Sort: usable first, then running, then by name
        results.sort(key=lambda x: (not x["usable"], x["status"] != "running", x["family"]))
        
        return results
    except Exception:
        return []


def _human_readable_time(dt) -> str:
    """Convert a datetime to human-readable relative time."""
    from datetime import datetime, timezone
    
    if dt is None:
        return "unknown"
    
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    diff = now - dt
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        mins = int(seconds / 60)
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    else:
        return dt.strftime("%Y-%m-%d")


# ANSI color codes
class Colors:
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _print_cluster_task_definitions(task_defs: list[dict], cluster_name: str) -> None:
    """Print a formatted list of task definitions from a cluster."""
    print(f"\n[cloud_run] Task definitions in cluster '{cluster_name}':\n", file=sys.stderr)

    if not task_defs:
        print("  (no task definitions found)\n", file=sys.stderr)
        return

    for td in task_defs:
        # Color-coded status
        if td["usable"]:
            icon = f"{Colors.GREEN}✓{Colors.RESET}"
            name_color = Colors.GREEN
        else:
            icon = f"{Colors.YELLOW}⚠{Colors.RESET}"
            name_color = Colors.YELLOW
        
        # Status string with color
        if td["status"] == "running":
            status_str = f"{Colors.GREEN}[running]{Colors.RESET}"
        else:
            status_str = f"{Colors.DIM}[stopped]{Colors.RESET}"
        
        if td["service"]:
            status_str += f" {Colors.CYAN}service:{td['service']}{Colors.RESET}"

        print(f"  {icon} {name_color}{td['family']}{Colors.RESET} {status_str}", file=sys.stderr)

        # Show last used time
        last_used = _human_readable_time(td.get("created_at"))
        print(f"      Last used: {last_used}", file=sys.stderr)

        # Show image (truncated)
        image = td["image"]
        if len(image) > 60:
            image = "..." + image[-57:]
        print(f"      {Colors.DIM}Image: {image}{Colors.RESET}", file=sys.stderr)

        # Show container info
        if td["container_count"] > 1:
            print(f"      Containers: {', '.join(td['containers'])}", file=sys.stderr)

        # Show warnings
        for warning in td["warnings"]:
            print(f"      {Colors.YELLOW}⚠ {warning}{Colors.RESET}", file=sys.stderr)

        print("", file=sys.stderr)


def _get_network_from_cluster(ecs, cluster_arn: str) -> Optional[dict]:
    """Try to infer network config (subnets, security groups) from cluster services or tasks."""
    
    # First try services - they have stable network configuration
    try:
        services_response = ecs.list_services(cluster=cluster_arn, maxResults=10)
        service_arns = services_response.get("serviceArns", [])
        
        if service_arns:
            services_detail = ecs.describe_services(cluster=cluster_arn, services=service_arns[:5])
            for service in services_detail.get("services", []):
                network_config = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
                subnets = network_config.get("subnets", [])
                security_groups = network_config.get("securityGroups", [])
                if subnets:
                    return {
                        "subnets": subnets,
                        "security_groups": security_groups,
                        "source": f"service {service.get('serviceName', 'unknown')}",
                    }
    except Exception:
        pass
    
    # Fall back to recent tasks
    try:
        # List recent tasks
        response = ecs.list_tasks(cluster=cluster_arn, maxResults=10)
        task_arns = response.get("taskArns", [])
        
        # Also check stopped tasks
        stopped_response = ecs.list_tasks(cluster=cluster_arn, desiredStatus="STOPPED", maxResults=10)
        task_arns.extend(stopped_response.get("taskArns", []))
        
        if not task_arns:
            return None
        
        # Get task details
        tasks_response = ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns[:5])
        tasks = tasks_response.get("tasks", [])
        
        # Find subnets and security groups from network configuration
        for task in tasks:
            attachments = task.get("attachments", [])
            subnets = []
            security_groups = []
            
            for attachment in attachments:
                if attachment.get("type") == "ElasticNetworkInterface":
                    for detail in attachment.get("details", []):
                        if detail.get("name") == "subnetId" and detail.get("value"):
                            subnets.append(detail["value"])
                        elif detail.get("name") == "networkInterfaceId":
                            # We could look up the ENI to get security groups
                            pass
            
            if subnets:
                return {
                    "subnets": list(set(subnets)),
                    "security_groups": security_groups,
                    "source": "recent task",
                }
        return None
    except Exception:
        return None


def _resolve_ecs_config(
    region: str,
    cluster_name: str,
    task_definition: Optional[str],
    vpc_name_or_id: Optional[str],
    subnet_ids: Optional[list[str]],
    security_group_ids: Optional[list[str]],
    cpu: str,
    memory: str,
    script_type: str,
    create_cluster: bool,
) -> ECSConfig:
    """
    Resolve all ECS configuration before running.
    Returns an ECSConfig with all resolved values.
    Raises RuntimeError if required values cannot be resolved.
    """
    ecs = boto3.client("ecs", region_name=region)
    
    config = ECSConfig(
        region=region,
        cluster_name=cluster_name,
        cpu=cpu,
        memory=memory,
        needs_new_task_def=not task_definition,
    )
    
    print("[cloud_run] Resolving ECS configuration...", file=sys.stderr)
    
    # 1. Resolve cluster
    cluster_arn = _get_cluster_arn(ecs, cluster_name)
    if cluster_arn:
        config.cluster_arn = cluster_arn
        print(f"[cloud_run]   Cluster: {cluster_name} ✓", file=sys.stderr)
    elif create_cluster:
        print(f"[cloud_run]   Cluster: {cluster_name} (will create)", file=sys.stderr)
    else:
        raise RuntimeError(
            f"Cluster '{cluster_name}' not found. Use --create-cluster to create it."
        )
    
    # 2. Resolve task definition
    if task_definition:
        try:
            response = ecs.describe_task_definition(taskDefinition=task_definition)
            task_def_info = response.get("taskDefinition", {})
            containers = task_def_info.get("containerDefinitions", [])

            if not containers:
                raise RuntimeError("Task definition has no containers")

            config.task_def_arn = task_def_info.get("taskDefinitionArn")
            config.task_family = task_def_info.get("family", "unknown")
            config.container_name = containers[0].get("name")

            # Extract log group
            log_config = containers[0].get("logConfiguration", {})
            if log_config.get("logDriver") == "awslogs":
                config.log_group = log_config.get("options", {}).get("awslogs-group")
            if not config.log_group:
                config.log_group = f"/ecs/{config.task_family}"

            print(f"[cloud_run]   Task definition: {task_definition} ✓", file=sys.stderr)
            print(f"[cloud_run]   Container: {config.container_name}", file=sys.stderr)
            
            # Check for potential issues and warn (but proceed since user specified explicitly)
            warnings = []
            
            # Check for multiple containers (sidecars)
            if len(containers) > 1:
                container_names = [c.get("name", "?") for c in containers]
                warnings.append(f"Has {len(containers)} containers: {container_names}")
                warnings.append("Only the first container's command will be overridden")
                warnings.append("Other containers (sidecars) will run with their default commands")
            
            # Check for entrypoint override in task def
            entrypoint = containers[0].get("entryPoint")
            if entrypoint:
                warnings.append(f"Has custom entryPoint: {entrypoint}")
                warnings.append("ECS doesn't allow overriding entryPoint - your script will run AFTER it")
            
            # Check image entrypoint
            image = containers[0].get("image", "")
            if image:
                image_info = _get_image_entrypoint(image, region)
                if image_info and image_info.get("safe") is False:
                    warnings.append(f"Image {image_info.get('reason')}")
                    warnings.append("ECS doesn't allow overriding entryPoint - your script may not run correctly")
            
            if warnings:
                print("[cloud_run]   ⚠ Warnings:", file=sys.stderr)
                for w in warnings:
                    print(f"[cloud_run]     - {w}", file=sys.stderr)
                print("[cloud_run]   Proceeding anyway (--task-definition was explicit)", file=sys.stderr)
                
        except ecs.exceptions.ClientException as e:
            raise RuntimeError(f"Task definition '{task_definition}' not found: {e}")
    else:
        # No task definition specified - list available ones and ask user to choose
        if cluster_arn:
            task_defs = _list_cluster_task_definitions(ecs, cluster_arn, region)
            
            if task_defs:
                _print_cluster_task_definitions(task_defs, cluster_name)
                
                # Build suggested command
                usable = [td for td in task_defs if td["usable"]]
                if usable:
                    suggested = usable[0]["family"]
                    print("[cloud_run] To run with a task definition:", file=sys.stderr)
                    print(f"  cloud_run <script> --ecs --cluster {cluster_name} --task-definition {suggested}\n", file=sys.stderr)
                else:
                    print("[cloud_run] No task definitions without warnings found.", file=sys.stderr)
                    print("  You can still use one with --task-definition (warnings will be shown).", file=sys.stderr)
                    print("  Or omit --cluster to let cloud_run create a new task definition.\n", file=sys.stderr)

                # Exit cleanly - this is an expected flow, not an error
                sys.exit(0)
            else:
                # No task definitions found in cluster - will create new one
                config.task_family = f"cloud-run-task-{script_type}"
                config.container_name = "script-runner"
                config.log_group = f"/ecs/{config.task_family}"
                print("[cloud_run]   No existing task definitions in cluster", file=sys.stderr)
                print(f"[cloud_run]   Task definition: {config.task_family} (will create)", file=sys.stderr)
                print(f"[cloud_run]   CPU: {cpu}, Memory: {memory}MB", file=sys.stderr)
        else:
            # No cluster yet - will create new task definition
            config.task_family = f"cloud-run-task-{script_type}"
            config.container_name = "script-runner"
            config.log_group = f"/ecs/{config.task_family}"
            print(f"[cloud_run]   Task definition: {config.task_family} (will create)", file=sys.stderr)
            print(f"[cloud_run]   CPU: {cpu}, Memory: {memory}MB", file=sys.stderr)
    
    # 3. Resolve network configuration (subnets and security groups)
    resolved_subnets: Optional[list[str]] = None
    resolved_security_groups: Optional[list[str]] = None
    network_source: Optional[str] = None
    
    # First try explicit values
    if subnet_ids:
        resolved_subnets = subnet_ids
        resolved_security_groups = security_group_ids
        network_source = "provided"
    # Then try VPC
    elif vpc_name_or_id:
        try:
            resolved_subnets = resolve_vpc_and_subnets(region, vpc_name_or_id, None)
            resolved_security_groups = security_group_ids
            network_source = f"VPC {vpc_name_or_id}"
        except Exception as e:
            print(f"[cloud_run]   Warning: Could not resolve VPC {vpc_name_or_id}: {e}", file=sys.stderr)
    
    # Then try to infer from cluster's services/tasks
    if not resolved_subnets and cluster_arn:
        network_config = _get_network_from_cluster(ecs, cluster_arn)
        if network_config:
            resolved_subnets = network_config["subnets"]
            if not resolved_security_groups and network_config.get("security_groups"):
                resolved_security_groups = network_config["security_groups"]
            network_source = f"inferred from {network_config['source']}"
    
    if resolved_subnets:
        config.subnet_ids = resolved_subnets
        config.security_group_ids = resolved_security_groups
        print(f"[cloud_run]   Subnets ({network_source}): {', '.join(resolved_subnets)}", file=sys.stderr)
        if resolved_security_groups:
            print(f"[cloud_run]   Security groups: {', '.join(resolved_security_groups)}", file=sys.stderr)
    else:
        raise RuntimeError(
            "Could not determine subnets. Provide --subnets or --vpc, "
            "or ensure a service is running in the cluster.\n"
            "Run 'cloud_run --list-vpcs' to see available VPCs and subnets."
        )
    
    print("[cloud_run] Configuration resolved ✓", file=sys.stderr)
    return config


def run_on_ecs(
    script_content: str,
    script_type: str,
    script_args: list,
    region: str,
    cpu: str,
    memory: str,
    task_definition: Optional[str] = None,
    cluster: Optional[str] = None,
    vpc_name_or_id: Optional[str] = None,
    subnet_ids: Optional[list[str]] = None,
    security_group_ids: Optional[list[str]] = None,
    create_cluster: bool = False,
    env_vars: Optional[dict[str, str]] = None,
    secrets: Optional[list[str]] = None,
) -> None:
    """Run script on ECS Fargate."""
    if not cluster:
        raise RuntimeError("--cluster is required for ECS tasks")
    
    try:
        # Phase 1: Resolve all configuration
        config = _resolve_ecs_config(
            region=region,
            cluster_name=cluster,
            task_definition=task_definition,
            vpc_name_or_id=vpc_name_or_id,
            subnet_ids=subnet_ids,
            security_group_ids=security_group_ids,
            cpu=cpu,
            memory=memory,
            script_type=script_type,
            create_cluster=create_cluster,
        )
        
        # Phase 2: Create any missing infrastructure
        print("[cloud_run] Preparing infrastructure...", file=sys.stderr)
        
        # Create cluster if needed
        if not config.cluster_arn:
            config.cluster_arn = ensure_ecs_cluster(cluster, region_name=region)
            print(f"[cloud_run]   Created cluster: {cluster}", file=sys.stderr)
        
        # Create task definition if needed
        if config.needs_new_task_def:
            assert config.task_family is not None, "task_family must be set"
            execution_role_arn = ensure_ecs_execution_role(region_name=region)
            config.task_def_arn = register_task_definition(
                family=config.task_family,
                execution_role_arn=execution_role_arn,
                script_type=script_type,
                cpu=cpu,
                memory=memory,
                region_name=region,
            )
            print(f"[cloud_run]   Registered task definition: {config.task_def_arn}", file=sys.stderr)
        
        # Validate required fields before running
        assert config.cluster_arn is not None, "cluster_arn must be resolved"
        assert config.task_def_arn is not None, "task_def_arn must be resolved"
        assert config.subnet_ids is not None, "subnet_ids must be resolved"
        assert config.container_name is not None, "container_name must be resolved"
        
        # Phase 3: Run the task
        print("[cloud_run] Starting ECS task...", file=sys.stderr)
        if script_args:
            print(f"[cloud_run] Script arguments: {script_args}", file=sys.stderr)
        if env_vars:
            print(f"[cloud_run] Environment variables: {list(env_vars.keys())}", file=sys.stderr)
        if secrets:
            print(f"[cloud_run] Secrets: {secrets}", file=sys.stderr)
        task_start = time.time()
        task_arn = run_ecs_task(
            cluster_arn=config.cluster_arn,
            task_definition_arn=config.task_def_arn,
            subnet_ids=config.subnet_ids,
            security_group_ids=config.security_group_ids,
            script_content=script_content,
            script_type=script_type,
            script_args=script_args,
            env_vars=env_vars,
            secrets=secrets,
            container_name=config.container_name,
            region_name=region,
        )
        task_id = task_arn.split("/")[-1]
        print(f"[cloud_run] Task started: {task_id}", file=sys.stderr)

        # Phase 4: Wait for completion (with live log streaming)
        print("[cloud_run] Waiting for task to complete...", file=sys.stderr)
        task_info = wait_for_task_completion(
            cluster_arn=config.cluster_arn,
            task_arn=task_arn,
            region_name=region,
            log_group=config.log_group,
            container_name=config.container_name,
        )
        task_duration = time.time() - task_start
        print(f"[cloud_run] Task completed in {task_duration:.2f}s", file=sys.stderr)

        # Get exit code and stopped reason
        container = task_info.get("containers", [{}])[0]
        exit_code = container.get("exitCode", 1)
        
        if exit_code == 0:
            print("[cloud_run] ✓ Task completed successfully", file=sys.stderr)
        else:
            print(f"[cloud_run] ✗ Task failed with exit code: {exit_code}", file=sys.stderr)
            
            # Show stopped reason only on failure
            stopped_reason = task_info.get("stoppedReason", "")
            if stopped_reason and "Essential container" not in stopped_reason:
                print(f"[cloud_run]   Stopped reason: {stopped_reason}", file=sys.stderr)
            
            container_reason = container.get("reason", "")
            if container_reason:
                print(f"[cloud_run]   Container reason: {container_reason}", file=sys.stderr)

        # Phase 5: Fetch and save logs (log_group and container_name already validated above)
        assert config.log_group is not None, "log_group must be resolved"
        print(f"[cloud_run] Fetching logs from {config.log_group}...", file=sys.stderr)
        logs = get_task_logs(
            config.log_group, 
            task_id, 
            container_name=config.container_name, 
            region_name=region
        )

        if logs:
            # Save logs to file
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)
            log_file = logs_dir / f"{task_id}.log"
            log_file.write_text(logs)
            print(f"[cloud_run] Logs saved to {log_file}", file=sys.stderr)
            print(logs)

        sys.exit(exit_code)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

