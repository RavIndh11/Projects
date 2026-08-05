import pytest
from src.security import check_container_create, check_read_only_mode, SecurityViolation
from src.config import settings

def test_safe_payload():
    payload = {
        "Image": "nginx:latest",
        "HostConfig": {
            "Binds": ["/var/log/nginx:/var/log/nginx:ro"]
        }
    }
    # Should not raise any exception
    check_container_create(payload)

def test_privileged_mode():
    payload = {
        "Image": "nginx:latest",
        "HostConfig": {
            "Privileged": True
        }
    }
    settings.allow_privileged_mode = False
    with pytest.raises(SecurityViolation, match="privileged containers is forbidden"):
        check_container_create(payload)

    settings.allow_privileged_mode = True
    check_container_create(payload) # Should pass now
    settings.allow_privileged_mode = False # Reset

def test_host_namespace_sharing():
    for mode in ["PidMode", "NetworkMode", "IpcMode", "UsernsMode"]:
        payload = {
            "HostConfig": {
                mode: "host"
            }
        }
        with pytest.raises(SecurityViolation, match="Host namespace sharing"):
            check_container_create(payload)

def test_dangerous_bind_mounts():
    dangerous_binds = [
        "/:/host",
        "/var/run/docker.sock:/var/run/docker.sock",
        "/etc:/host/etc",
        "/root:/host/root",
        "/var/lib/docker:/host/docker"
    ]
    for bind in dangerous_binds:
        payload = {
            "HostConfig": {
                "Binds": [bind]
            }
        }
        with pytest.raises(SecurityViolation, match="Mounting dangerous host paths"):
            check_container_create(payload)

def test_dangerous_capabilities():
    payload = {
        "HostConfig": {
            "CapAdd": ["SYS_ADMIN"]
        }
    }
    with pytest.raises(SecurityViolation, match="Adding dangerous capability"):
        check_container_create(payload)

def test_read_only_mode():
    settings.read_only_mode = True

    # Allowed
    check_read_only_mode("GET")
    check_read_only_mode("HEAD")
    check_read_only_mode("OPTIONS")

    # Blocked
    with pytest.raises(SecurityViolation, match="forbidden in read-only mode"):
        check_read_only_mode("POST")
    with pytest.raises(SecurityViolation, match="forbidden in read-only mode"):
        check_read_only_mode("DELETE")

    settings.read_only_mode = False
