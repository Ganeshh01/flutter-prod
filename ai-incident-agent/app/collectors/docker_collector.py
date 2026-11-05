import docker
from docker.errors import DockerException, NotFound


def list_running_containers() -> dict:
    """Collect information about currently running Docker containers."""

    try:
        client = docker.from_env()
        containers = client.containers.list()

        results = []

        for container in containers:
            container.reload()

            results.append({
                "container_id": container.short_id,
                "name": container.name,
                "image": container.image.tags,
                "status": container.status,
                "restart_count": container.attrs.get("RestartCount", 0)
            })

        client.close()

        return {
            "collector": "docker",
            "status": "success",
            "container_count": len(results),
            "containers": results
        }

    except DockerException as error:
        return {
            "collector": "docker",
            "status": "error",
            "evidence": str(error)
        }


def get_container_logs(container_id: str, tail: int = 100) -> dict:
    """Collect recent logs from a specific container."""

    client = None

    try:
        client = docker.from_env()
        container = client.containers.get(container_id)

        logs = container.logs(
            tail=tail,
            timestamps=True
        ).decode("utf-8", errors="replace")

        return {
            "collector": "docker",
            "container_id": container.short_id,
            "container_name": container.name,
            "container_status": container.status,
            "logs": logs,
            "evidence": "Recent container logs collected successfully."
        }

    except NotFound:
        return {
            "collector": "docker",
            "status": "error",
            "evidence": f"Container '{container_id}' was not found."
        }

    except DockerException as error:
        return {
            "collector": "docker",
            "status": "error",
            "evidence": str(error)
        }

    finally:
        if client is not None:
            client.close()