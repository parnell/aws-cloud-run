from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

import boto3


def parse_ecr_image_uri(image_uri: str) -> dict[str, str | None] | None:
    """Parse an ECR image URI into its components.

    Returns dict with keys:
      - account
      - region
      - repository
      - tag (defaults to 'latest' when absent)
      - digest (None unless provided as @sha256:...)
    """
    # ECR format: <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>
    # or: <account>.dkr.ecr.<region>.amazonaws.com/<repo>@sha256:<digest>
    ecr_pattern = r"^(\d+)\.dkr\.ecr\.([^.]+)\.amazonaws\.com/([^:@]+)(?::([^@]+)|@(.+))?$"
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


def get_image_entrypoint(image_uri: str, region: str) -> dict[str, Any] | None:
    """Inspect an image (if in ECR) and return entrypoint/cmd safety info.

    Returns a dict with:
      - entrypoint: list | None
      - cmd: list | None
      - safe: bool | None
      - reason: str

    Returns None if unable to inspect (image missing, not accessible, etc.).
    """
    parsed = parse_ecr_image_uri(image_uri)
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
        image_id = (
            {"imageTag": parsed["tag"]} if parsed["tag"] else {"imageDigest": parsed["digest"]}
        )

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
        with urllib.request.urlopen(blob_response["downloadUrl"]) as resp:
            config = json.loads(resp.read().decode())

        # Extract entrypoint and cmd from config
        container_config = config.get("config", {})
        entrypoint = container_config.get("Entrypoint")
        cmd = container_config.get("Cmd")

        # Determine if it's safe for command override
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
