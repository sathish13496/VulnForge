"""
LinArmor Engine — Scan Orchestrator

Manages the complete scan lifecycle through 6 phases:
1. Reconnaissance  — Host discovery
2. Enumeration     — Port scanning & service detection
3. Vulnerability Discovery — Running scan modules
4. Exploitation    — Validating exploitable findings (future)
5. Post-Exploitation — Impact assessment (future)
6. Reporting       — Generating reports

Emits real-time events for the frontend via WebSocket.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Callable, Optional

from linarmor.config import (
    AUTH_REQUIRED_MODULES,
    MAX_THREADS,
    SCAN_TYPES,
)
from linarmor.core.scanner import NmapScanner
from linarmor.core.target import Finding, ScanStatus, Target

logger = logging.getLogger("linarmor.engine")


class ScanEngine:
    """
    Central orchestrator that coordinates the full scan pipeline.

    Usage:
        engine = ScanEngine(log_callback=emit_to_websocket)
        engine.configure(ip="192.168.1.100", scan_type="full", modules=[...])
        engine.start()       # Runs in a background thread
        engine.pause()
        engine.resume()
        engine.stop()
    """

    # ──────────────────────────────────────────────
    # Phase definitions for the methodology pipeline
    # ──────────────────────────────────────────────
    PHASES = [
        {"name": "Reconnaissance", "description": "Host discovery and OS fingerprinting"},
        {"name": "Enumeration", "description": "Port scanning and service detection"},
        {"name": "Vulnerability Discovery", "description": "Analyzing configurations for weaknesses"},
        {"name": "Exploitation", "description": "Validating exploitable vulnerabilities"},
        {"name": "Post-Exploitation", "description": "Assessing impact and lateral movement"},
        {"name": "Reporting", "description": "Generating comprehensive security report"},
    ]

    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None):
        """
        Args:
            log_callback: Function(level, message) for real-time log output.
        """
        self._log_callback = log_callback or self._default_log
        self._scanner = NmapScanner(log_callback=self._log_callback)
        self._target: Optional[Target] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._modules: dict[str, object] = {}  # module_name -> module instance
        self._pause_event = threading.Event()
        self._stop_event = threading.Event()
        self._pause_event.set()  # Not paused by default
        self._current_phase: int = 0
        self._progress: float = 0.0
        self._status_callback: Optional[Callable[[dict], None]] = None

    def _default_log(self, level: str, message: str) -> None:
        log_fn = getattr(logger, level if level != "success" else "info")
        log_fn(message)

    def _emit(self, level: str, message: str) -> None:
        """Emit a log message."""
        self._log_callback(level, message)

    def _emit_status(self) -> None:
        """Emit current scan status to the frontend."""
        if self._status_callback and self._target:
            self._status_callback(self.get_status())

    # ──────────────────────────────────────────────
    # Configuration
    # ──────────────────────────────────────────────

    def _reset_state(self) -> None:
        """Reset internal engine state for a fresh scan."""
        self._stop_event.clear()
        self._pause_event.set()  # Not paused
        self._current_phase = 0
        self._progress = 0.0

    def configure(
        self,
        ip: str,
        scan_type: str = "full",
        port_range: Optional[str] = None,
        modules: Optional[list[str]] = None,
    ) -> None:
        """
        Configure the scan target and parameters.

        Args:
            ip: Target IP address
            scan_type: "full", "quick", or "custom"
            port_range: Custom port range (e.g., "1-1000"). Uses scan_type default if None.
            modules: List of module names to run. Uses scan_type default if None.
        """
        # Reset engine state for a fresh scan
        self._reset_state()

        scan_config = SCAN_TYPES.get(scan_type, SCAN_TYPES["full"])

        self._target = Target(
            ip=ip,
            port_range=port_range or scan_config["port_range"],
            scan_type=scan_type,
            modules_selected=modules or scan_config["modules"],
        )

        self._emit("info", f"Scan configured: target={ip}, type={scan_type}, "
                    f"ports={self._target.port_range}, "
                    f"modules={len(self._target.modules_selected)}")

    def set_status_callback(self, callback: Callable[[dict], None]) -> None:
        """Set a callback to receive status updates."""
        self._status_callback = callback

    def register_module(self, name: str, module_instance: object) -> None:
        """Register a scan module by name."""
        self._modules[name] = module_instance

    # ──────────────────────────────────────────────
    # Scan Lifecycle
    # ──────────────────────────────────────────────

    def start(self) -> None:
        """Start the scan in a background thread."""
        if not self._target:
            self._emit("error", "No target configured. Call configure() first.")
            return

        # Check if a scan thread is truly still active
        if self._scan_thread and self._scan_thread.is_alive():
            # If the scan is in a terminal state but thread hasn't exited yet,
            # wait briefly for it to finish
            if self._target.scan_status in (
                ScanStatus.STOPPED, ScanStatus.COMPLETED, ScanStatus.ERROR
            ):
                self._scan_thread.join(timeout=3)
            else:
                self._emit("warn", "Scan is already running")
                return

        # Final check after potential join
        if self._scan_thread and self._scan_thread.is_alive():
            self._emit("warn", "Scan is already running")
            return

        self._stop_event.clear()
        self._pause_event.set()
        self._target.scan_status = ScanStatus.RUNNING
        self._target.start_time = datetime.now()

        self._scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self._scan_thread.start()
        self._emit("info", f"Initializing scan engine for target {self._target.ip}")

    def pause(self) -> None:
        """Pause the running scan."""
        if self._target:
            self._pause_event.clear()
            self._target.scan_status = ScanStatus.PAUSED
            self._emit("warn", "Scan paused")
            self._emit_status()

    def resume(self) -> None:
        """Resume a paused scan."""
        if self._target:
            self._pause_event.set()
            self._target.scan_status = ScanStatus.RUNNING
            self._emit("info", "Scan resumed")
            self._emit_status()

    def stop(self) -> None:
        """Stop the scan and wait for the thread to terminate."""
        self._stop_event.set()
        self._pause_event.set()  # Unblock if paused
        if self._target:
            self._target.scan_status = ScanStatus.STOPPED
            self._target.end_time = datetime.now()
            self._emit("warn", "Scan stopped by user")
            self._emit_status()

        # Wait for the scan thread to actually finish
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=5)
        self._scan_thread = None

    @property
    def is_running(self) -> bool:
        return (self._scan_thread is not None and
                self._scan_thread.is_alive())

    # ──────────────────────────────────────────────
    # Main Scan Pipeline
    # ──────────────────────────────────────────────

    def _run_scan(self) -> None:
        """Execute the full scan pipeline. Runs in a background thread."""
        try:
            # ── Phase 1: Reconnaissance ──
            self._set_phase(0, 0)
            if self._should_stop():
                return
            self._scanner.discover_host(self._target)
            self._set_phase(0, 100)

            if not self._target.is_alive:
                self._emit("error", f"Target {self._target.ip} is not reachable. Scan aborted.")
                self._target.scan_status = ScanStatus.ERROR
                self._emit_status()
                return

            # ── Phase 2: Enumeration ──
            self._set_phase(1, 0)
            if self._should_stop():
                return
            scan_mode = "quick" if self._target.scan_type == "quick" else "full"
            self._scanner.scan_ports(self._target, scan_type=scan_mode)
            self._scanner.grab_banners(self._target)
            self._set_phase(1, 100)

            # ── Phase 3: Vulnerability Discovery ──
            self._set_phase(2, 0)
            if self._should_stop():
                return
            self._run_modules()
            self._set_phase(2, 100)

            # ── Phase 4: Exploitation (placeholder) ──
            self._set_phase(3, 0)
            if self._should_stop():
                return
            self._emit("info", "Phase 4: Exploitation — Validating exploitable findings")
            # Future: Attempt exploitation of confirmed vulnerabilities
            self._set_phase(3, 100)

            # ── Phase 5: Post-Exploitation (placeholder) ──
            self._set_phase(4, 0)
            if self._should_stop():
                return
            self._emit("info", "Phase 5: Post-Exploitation — Assessing impact")
            # Future: Check for lateral movement, data access
            self._set_phase(4, 100)

            # ── Phase 6: Reporting ──
            self._set_phase(5, 0)
            if self._should_stop():
                return
            self._emit("info", "Phase 6: Reporting — Compiling results")
            self._set_phase(5, 100)

            # ── Complete ──
            self._target.scan_status = ScanStatus.COMPLETED
            self._target.end_time = datetime.now()
            self._progress = 100.0

            self._emit("success",
                        f"Scan completed in {self._target.elapsed_time} — "
                        f"{self._target.total_findings} findings discovered")
            self._emit_status()

        except Exception as e:
            logger.exception("Scan engine error")
            self._emit("error", f"Scan engine error: {e}")
            if self._target:
                self._target.scan_status = ScanStatus.ERROR
                self._target.end_time = datetime.now()
                self._emit_status()
        finally:
            # Always clear the thread reference so start() won't see a stale thread
            self._scan_thread = None

    def _run_modules(self) -> None:
        """Run all selected scan modules against the target."""
        selected = self._target.modules_selected
        total = len(selected)

        self._emit("info", f"Phase 3: Vulnerability Discovery — Running {total} modules")

        for i, module_name in enumerate(selected):
            if self._should_stop():
                return

            # Wait if paused
            self._pause_event.wait()

            # Check if module requires auth
            if module_name in AUTH_REQUIRED_MODULES:
                self._emit("warn",
                           f"Module '{module_name}' requires authenticated access — skipping "
                           f"(unauthenticated scan mode)")
                continue

            # Get module instance
            module = self._modules.get(module_name)
            if not module:
                self._emit("warn", f"Module '{module_name}' not registered — skipping")
                continue

            # Run the module
            self._emit("info", f"Running module: {module.name} [{i+1}/{total}]")
            try:
                findings = module.scan(self._target)
                for finding in findings:
                    self._target.add_finding(finding)
                    if finding.cve_id:
                        self._emit("error",
                                   f"{finding.cve_id} — {finding.title} — CVSS {finding.cvss_score}")
                    else:
                        level = "warn" if finding.severity.value in ("critical", "high") else "info"
                        self._emit(level, f"{finding.title} — {finding.severity.value.upper()}")

                self._emit("success",
                           f"Module '{module.name}' completed — {len(findings)} findings")
            except Exception as e:
                self._emit("error", f"Module '{module_name}' failed: {e}")

            # Update progress within phase 3
            phase_progress = ((i + 1) / total) * 100
            self._set_phase(2, phase_progress)

    # ──────────────────────────────────────────────
    # Progress Tracking
    # ──────────────────────────────────────────────

    def _set_phase(self, phase_index: int, phase_progress: float) -> None:
        """Update current phase and overall progress."""
        self._current_phase = phase_index
        # Each phase is ~16.67% of total progress (6 phases)
        phase_weight = 100.0 / len(self.PHASES)
        self._progress = (phase_index * phase_weight) + (phase_progress * phase_weight / 100.0)
        self._emit_status()

    def _should_stop(self) -> bool:
        """Check if the scan should stop."""
        return self._stop_event.is_set()

    # ──────────────────────────────────────────────
    # Status
    # ──────────────────────────────────────────────

    def get_status(self) -> dict:
        """Get the current scan status as a dict for the frontend."""
        if not self._target:
            return {"status": "idle", "progress": 0}

        phase = self.PHASES[self._current_phase] if self._current_phase < len(self.PHASES) else None

        return {
            "status": self._target.scan_status.value,
            "progress": round(self._progress, 1),
            "phase": phase["name"] if phase else "Complete",
            "phase_description": phase["description"] if phase else "",
            "phase_index": self._current_phase,
            "elapsed_time": self._target.elapsed_time,
            "target_ip": self._target.ip,
            "modules_active": len(self._target.modules_selected),
            "findings_count": self._target.total_findings,
            "severity_counts": self._target.severity_counts,
            "phase_results": self._get_phase_results(),
        }

    def _get_phase_results(self) -> list:
        """Generate human-readable result labels for each pipeline phase."""
        if not self._target:
            return ["—"] * 6

        t = self._target
        results = ["—"] * 6

        # Phase 0: Reconnaissance
        if self._current_phase > 0 or self._target.scan_status.value == "completed":
            if t.is_alive:
                results[0] = f"Host: UP ({t.os_family or 'Unknown OS'})"
            else:
                results[0] = "Host: DOWN"
        elif self._current_phase == 0 and self._progress > 0:
            results[0] = "Scanning..."

        # Phase 1: Enumeration
        if self._current_phase > 1 or self._target.scan_status.value == "completed":
            results[1] = f"{len(t.open_ports)} ports · {len(t.services)} services"
        elif self._current_phase == 1:
            results[1] = "Scanning..."

        # Phase 2: Vulnerability Discovery
        if self._current_phase > 2 or self._target.scan_status.value == "completed":
            results[2] = f"{t.total_findings} findings"
        elif self._current_phase == 2:
            results[2] = f"{t.total_findings} found..."

        # Phase 3: Exploitation
        if self._current_phase > 3 or self._target.scan_status.value == "completed":
            crit = t.severity_counts.get("critical", 0)
            high = t.severity_counts.get("high", 0)
            results[3] = f"{crit + high} exploitable"
        elif self._current_phase == 3:
            results[3] = "Validating..."

        # Phase 4: Post-Exploitation
        if self._current_phase > 4 or self._target.scan_status.value == "completed":
            results[4] = "Assessment done"
        elif self._current_phase == 4:
            results[4] = "Assessing..."

        # Phase 5: Reporting
        if self._target.scan_status.value == "completed":
            results[5] = "Report ready"
        elif self._current_phase == 5:
            results[5] = "Compiling..."

        return results


    def get_target(self) -> Optional[Target]:
        """Get the current target with all findings."""
        return self._target

    def get_findings(self) -> list[dict]:
        """Get all findings as dicts for the API."""
        if not self._target:
            return []
        return [f.to_dict() for f in self._target.findings]
