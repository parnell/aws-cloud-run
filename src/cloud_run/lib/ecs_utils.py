from __future__ import annotations

from .aws_auth import aws_auth_error_message, is_aws_auth_error
from .ecr_utils import get_image_entrypoint


def get_cluster_arn(ecs, cluster_name: str) -> str | None:
    """Get cluster ARN if it exists, None otherwise."""
    try:
        response = ecs.describe_clusters(clusters=[cluster_name])
        active_clusters = [c for c in response.get("clusters", []) if c["status"] == "ACTIVE"]
        if active_clusters:
            return active_clusters[0]["clusterArn"]
    except Exception as e:
        if is_aws_auth_error(e):
            raise RuntimeError(aws_auth_error_message()) from e
        raise RuntimeError(f"Failed to look up ECS cluster '{cluster_name}': {e}") from e
    return None


def list_cluster_task_definitions(ecs, cluster_arn: str, region: str) -> list[dict]:
    """List unique task definitions used by recent tasks in a cluster."""
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
        seen_families: dict[str, dict] = {}

        for task in tasks:
            task_def_arn = task.get("taskDefinitionArn")
            if not task_def_arn:
                continue

            # Extract family from ARN
            family = task_def_arn.split("/")[-1].rsplit(":", 1)[0]

            # Keep the most recent/relevant task for each family (prefer running)
            if family in seen_families and seen_families[family]["status"] == "running":
                continue

            status = "running" if task.get("lastStatus") == "RUNNING" else "stopped"
            started_by = task.get("startedBy", "")
            service = None
            if started_by.startswith("ecs-svc/"):
                group = task.get("group", "")
                if group.startswith("service:"):
                    service = group[8:]

            seen_families[family] = {
                "task_def_arn": task_def_arn,
                "status": status,
                "service": service,
                "created_at": task.get("createdAt"),
            }

        results: list[dict] = []

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

            warnings: list[str] = []
            usable = True

            # Check for multiple containers
            if len(containers) > 1:
                warnings.append(
                    f"Has {len(containers)} containers (sidecars will also run): {container_names}"
                )
                usable = False

            # Check for entrypoint override in task def
            entrypoint = first_container.get("entryPoint")
            if entrypoint:
                warnings.append(f"Has custom entryPoint: {entrypoint}")
                usable = False

            # Check image entrypoint
            if image:
                image_info = get_image_entrypoint(image, region)
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


def infer_network_from_cluster(ecs, cluster_arn: str) -> dict | None:
    """Infer network config (subnets, security groups) from cluster services or tasks."""
    # First try services - they have stable network configuration
    try:
        services_response = ecs.list_services(cluster=cluster_arn, maxResults=10)
        service_arns = services_response.get("serviceArns", [])

        if service_arns:
            services_detail = ecs.describe_services(cluster=cluster_arn, services=service_arns[:5])
            for service in services_detail.get("services", []):
                network_config = service.get("networkConfiguration", {}).get(
                    "awsvpcConfiguration", {}
                )
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
        response = ecs.list_tasks(cluster=cluster_arn, maxResults=10)
        task_arns = response.get("taskArns", [])

        stopped_response = ecs.list_tasks(
            cluster=cluster_arn, desiredStatus="STOPPED", maxResults=10
        )
        task_arns.extend(stopped_response.get("taskArns", []))

        if not task_arns:
            return None

        tasks_response = ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns[:5])
        tasks = tasks_response.get("tasks", [])

        for task in tasks:
            attachments = task.get("attachments", [])
            subnets: list[str] = []
            security_groups: list[str] = []

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
