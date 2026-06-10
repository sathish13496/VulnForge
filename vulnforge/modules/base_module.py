"""
VulnForge Base Module

Abstract base class that all scan modules must extend.
Provides a consistent interface for the scan engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Optional

from vulnforge.core.target import Finding, Target


class BaseModule(ABC):
    """
    Abstract base class for all VulnForge scan modules.

    Every scan module must implement:
        - name: Human-readable module name
        - description: What this module checks
        - scan(): Execute the scan and return findings

    Example:
        class SSHModule(BaseModule):
            name = "Insecure SSH Settings"
            description = "Checks SSH configurations for security issues"

            def scan(self, target: Target) -> list[Finding]:
                findings = []
                # ... scanning logic ...
                return findings
    """

    name: str = "Base Module"
    description: str = ""
    module_id: str = ""       # Short ID, e.g., "ssh", "kernel"
    requires_auth: bool = False  # Whether module needs SSH access

    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None):
        self._log = log_callback or (lambda level, msg: None)

    def _emit(self, level: str, message: str) -> None:
        """Emit a log message."""
        self._log(level, message)

    @abstractmethod
    def scan(self, target: Target) -> list[Finding]:
        """
        Execute the scan module against the target.

        Args:
            target: The Target object containing IP, open ports, services, etc.

        Returns:
            List of Finding objects discovered by this module.
        """
        pass
