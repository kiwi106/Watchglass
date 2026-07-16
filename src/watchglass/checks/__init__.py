"""Built-in static checks."""

from collections.abc import Callable

from watchglass.checks.config import check_config
from watchglass.checks.docker import check_dockerfile
from watchglass.checks.github_actions import check_github_actions
from watchglass.checks.secrets import check_secrets
from watchglass.checks.sensitive import check_sensitive_files
from watchglass.core.files import ScannedFile
from watchglass.models import Finding

Check = Callable[[ScannedFile], list[Finding]]
ALL_CHECKS: tuple[Check, ...] = (
    check_secrets,
    check_sensitive_files,
    check_config,
    check_dockerfile,
    check_github_actions,
)

__all__ = ["ALL_CHECKS"]
