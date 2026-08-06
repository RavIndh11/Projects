from typing import Any, Dict, List, Optional
from src.config import settings
from src.logger import logger

class SecurityViolation(Exception):
    pass

def check_container_create(payload: Dict[str, Any]) -> None:
    """
    Inspects Docker container creation payload and blocks dangerous configurations.
    """
    host_config = payload.get("HostConfig", {})

    # Check Privileged Mode
    if not settings.allow_privileged_mode and host_config.get("Privileged", False):
        logger.warning("Security violation: Privileged mode requested", extra={"payload": payload})
        raise SecurityViolation("Creating privileged containers is forbidden.")

    # Check Host Namespace sharing
    for mode in ["PidMode", "NetworkMode", "IpcMode", "UsernsMode"]:
        if host_config.get(mode, "") == "host":
             logger.warning(f"Security violation: {mode} host requested", extra={"payload": payload})
             raise SecurityViolation(f"Host namespace sharing ({mode}='host') is forbidden.")

    # Check Dangerous Mounts
    binds = host_config.get("Binds", []) or []
    dangerous_mounts = ["/", "/var/run/docker.sock", "/etc", "/root", "/var/lib/docker"]
    for bind in binds:
        host_path = bind.split(":")[0] if ":" in bind else bind
        if host_path in dangerous_mounts or any(host_path.startswith(dm + "/") for dm in dangerous_mounts):
             logger.warning(f"Security violation: Dangerous bind mount requested ({host_path})", extra={"payload": payload})
             raise SecurityViolation(f"Mounting dangerous host paths ({host_path}) is forbidden.")

    # Check Capabilities
    cap_add = host_config.get("CapAdd", []) or []
    dangerous_caps = ["ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH"]
    for cap in cap_add:
        if cap.upper() in dangerous_caps:
            logger.warning(f"Security violation: Dangerous capability requested ({cap})", extra={"payload": payload})
            raise SecurityViolation(f"Adding dangerous capability ({cap}) is forbidden.")

def check_read_only_mode(method: str) -> None:
    """
    Blocks modifying methods if read_only_mode is enabled.
    """
    if settings.read_only_mode and method.upper() not in ["GET", "HEAD", "OPTIONS"]:
        logger.warning(f"Security violation: Write operation attempted in read-only mode ({method})")
        raise SecurityViolation(f"Operation ({method}) forbidden in read-only mode.")
