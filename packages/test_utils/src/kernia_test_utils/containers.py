"""Lazy testcontainers fixtures.

Each helper imports `testcontainers` at call-time so the dep stays optional.
If Docker is not reachable, the call raises an ImportError / RuntimeError; use
`requires_docker()` to skip cleanly at the test layer.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess
from collections.abc import Iterator

import pytest


def _testcontainers_installed() -> bool:
    """True if the optional `testcontainers` package is importable."""
    import importlib.util

    return importlib.util.find_spec("testcontainers") is not None


def docker_available() -> bool:
    """Best-effort check that container-backed tests can actually run.

    Requires BOTH a reachable Docker daemon AND the `testcontainers` package.
    If either is missing, the gated suites skip cleanly instead of erroring —
    a Docker daemon with no `testcontainers` install is a common local setup.
    """
    if not _testcontainers_installed():
        return False
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def requires_docker() -> pytest.MarkDecorator:
    """Return a pytest mark that skips when Docker isn't reachable."""
    return pytest.mark.skipif(
        not docker_available(), reason="Docker is not available on this host"
    )


@contextlib.contextmanager
def postgres_container(image: str = "postgres:16-alpine") -> Iterator[str]:
    """Yield a Postgres connection URL (asyncpg-compatible)."""
    try:
        from testcontainers.postgres import PostgresContainer  # type: ignore[import-not-found]
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("testcontainers extra is not installed") from e
    container = PostgresContainer(image)
    container.start()
    try:
        # Convert default psycopg2 URL to asyncpg-friendly form.
        url = container.get_connection_url().replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )
        yield url
    finally:
        container.stop()


@contextlib.contextmanager
def mysql_container(image: str = "mysql:8") -> Iterator[str]:
    try:
        from testcontainers.mysql import MySqlContainer  # type: ignore[import-not-found]
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("testcontainers extra is not installed") from e
    container = MySqlContainer(image)
    container.start()
    try:
        url = container.get_connection_url().replace(
            "mysql+pymysql://", "mysql+aiomysql://"
        )
        yield url
    finally:
        container.stop()


@contextlib.contextmanager
def mongodb_container(image: str = "mongo:7") -> Iterator[str]:
    try:
        from testcontainers.mongodb import MongoDbContainer  # type: ignore[import-not-found]
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("testcontainers extra is not installed") from e
    container = MongoDbContainer(image)
    container.start()
    try:
        yield container.get_connection_url()
    finally:
        container.stop()


@contextlib.contextmanager
def redis_container(image: str = "redis:7-alpine") -> Iterator[str]:
    try:
        from testcontainers.redis import RedisContainer  # type: ignore[import-not-found]
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("testcontainers extra is not installed") from e
    container = RedisContainer(image)
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"
    finally:
        container.stop()


__all__ = [
    "docker_available",
    "mongodb_container",
    "mysql_container",
    "postgres_container",
    "redis_container",
    "requires_docker",
]
