import ctypes
import json
import platform
import shutil
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

from core import AuditFinding, get_text, __version__, __repo__


class AuditReporter:
    """Renders structured terminal tables, executive summaries, and JSON compliance reports."""

    def __init__(self, lang: str = "en", console: Optional[Console] = None) -> None:
        self.lang = lang.lower() if lang.lower() in ("en", "id") else "en"
        if console is not None:
            self.console = console
        else:
            term_cols = shutil.get_terminal_size((128, 40)).columns
            effective_width = max(term_cols, 120) if not sys.stdout.isatty() else max(term_cols, 100)
            self.console = Console(width=effective_width, highlight=False)

    @staticmethod
    def is_user_admin() -> bool:
        """Check whether the current process holds administrative privileges."""
        if sys.platform == "win32":
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            except Exception:
                return False
        try:
            return hasattr(sys, "getwindowsversion")
        except Exception:
            return False

    def get_host_metadata(self) -> Dict[str, Any]:
        """Collect non-invasive host identification metadata for audit context."""
        is_admin = self.is_user_admin()
        priv_label = (
            get_text(self.lang, "lbl_priv_admin")
            if is_admin
            else get_text(self.lang, "lbl_priv_user")
        )
        return {
            "tool": "WinHardener",
            "version": __version__,
            "repository": __repo__,
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hostname": socket.gethostname(),
            "os_platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "python_version": platform.python_version(),
            "is_elevated": is_admin,
            "execution_context": priv_label,
            "language": self.lang,
        }

    @staticmethod
    def compute_posture_metrics(findings: List[AuditFinding]) -> Dict[str, Any]:
        """
        Calculate deterministic security posture compliance metrics:
        - Total vectors tested
        - Pass count, Info count, Medium risk count, High/Critical risk count
        - Weighted compliance score percentage (0.0 - 100.0%)
        """
        total = len(findings)
        if total == 0:
            return {
                "total_vectors": 0,
                "pass_count": 0,
                "info_count": 0,
                "medium_count": 0,
                "critical_high_count": 0,
                "compliance_score_pct": 100.0,
                "risk_tier": "LOW",
            }

        pass_count = sum(1 for f in findings if f.status.upper() == "PASS")
        info_count = sum(1 for f in findings if f.status.upper() == "INFO")
        medium_count = sum(1 for f in findings if f.status.upper() == "MEDIUM")
        crit_high_count = sum(1 for f in findings if f.status.upper() in ("HIGH", "CRITICAL"))

        # Weighted calculation: PASS/INFO = 1.0 point, MEDIUM = 0.4 point, HIGH/CRITICAL = 0.0 points
        earned_points = (pass_count * 1.0) + (info_count * 1.0) + (medium_count * 0.4)
        score_pct = round((earned_points / total) * 100.0, 1)

        if crit_high_count > 0:
            risk_tier = "HIGH"
        elif medium_count > 0:
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        return {
            "total_vectors": total,
            "pass_count": pass_count,
            "info_count": info_count,
            "medium_count": medium_count,
            "critical_high_count": crit_high_count,
            "compliance_score_pct": score_pct,
            "risk_tier": risk_tier,
        }

    def create_progress_bar(self) -> Progress:
        """Create a calm, functional progress bar for audit execution phases."""
        return Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[white]{task.description}[/white]"),
            BarColumn(bar_width=36, style="grey37", complete_style="cyan", finished_style="green"),
            TaskProgressColumn(),
            console=self.console,
            transient=True,
        )

    def render_header_panel(self, host_meta: Dict[str, Any]) -> None:
        """Render the concise status header panel at the start of CLI output."""
        title_str = get_text(self.lang, "app_title")
        subtitle_str = get_text(self.lang, "app_subtitle")

        header_grid = Table.grid(padding=(0, 2))
        header_grid.add_column(style="bold white")
        header_grid.add_column(style="white")
        header_grid.add_row(
            f"{get_text(self.lang, 'lbl_host')}:",
            f"{host_meta['hostname']}  |  {get_text(self.lang, 'lbl_os')}: {host_meta['os_platform']}",
        )
        header_grid.add_row(
            f"{get_text(self.lang, 'lbl_priv')}:",
            f"{host_meta['execution_context']}  |  Repository: {__repo__}",
        )

        panel = Panel(
            header_grid,
            title=f"[bold white]{title_str} (v{__version__})[/bold white]",
            subtitle=f"[dim]{subtitle_str}[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 2),
        )
        self.console.print()
        self.console.print(panel)

        if sys.platform != "win32":
            self.console.print(
                f" [cyan]{get_text(self.lang, 'badge_info')}[/cyan] [dim]{get_text(self.lang, 'sim_notice')}[/dim]"
            )
        self.console.print()

    def _format_status_badge(self, status: str) -> Text:
        """Map finding status to calm, standardized functional color badges."""
        st = status.upper()
        if st == "PASS":
            return Text(get_text(self.lang, "badge_pass"), style="green")
        if st == "INFO":
            return Text(get_text(self.lang, "badge_info"), style="cyan")
        if st == "MEDIUM":
            return Text(get_text(self.lang, "badge_medium"), style="yellow")
        return Text(get_text(self.lang, "badge_high"), style="bold red")

    def render_master_audit_table(self, findings: List[AuditFinding]) -> None:
        """Render the Master Audit Table with balanced padding and clear column hierarchy."""
        table = Table(
            title=f"[bold white]{get_text(self.lang, 'master_table_title')}[/bold white]",
            box=box.SIMPLE_HEAVY,
            header_style="bold white",
            border_style="grey50",
            padding=(0, 1),
            expand=True,
            show_lines=True,
        )

        table.add_column(get_text(self.lang, "col_id"), style="cyan", min_width=8, ratio=1, no_wrap=True)
        table.add_column(get_text(self.lang, "col_category"), style="white", min_width=12, ratio=1)
        table.add_column(get_text(self.lang, "col_vector"), style="white", min_width=22, ratio=3)
        table.add_column(get_text(self.lang, "col_reference"), style="dim white", min_width=14, ratio=2)
        table.add_column(get_text(self.lang, "col_state"), style="white", min_width=18, ratio=2)
        table.add_column(get_text(self.lang, "col_status"), justify="center", min_width=18, ratio=2, no_wrap=True)
        table.add_column(get_text(self.lang, "col_remediation"), style="white", min_width=22, ratio=3)

        for item in findings:
            vector_cell = f"[bold]{item.title}[/bold]\n[dim]{item.target}[/dim]"
            ref_cell = f"MITRE: {item.mitre_id}\n{item.cis_ref}"
            state_cell = f"{item.current_value}\n[dim]Expected: {item.expected_value}[/dim]"
            badge_cell = self._format_status_badge(item.status)

            table.add_row(
                item.vector_id,
                item.category,
                vector_cell,
                ref_cell,
                state_cell,
                badge_cell,
                item.remediation_summary,
            )

        self.console.print(table)
        self.console.print()

    def render_executive_summary(
        self,
        findings: List[AuditFinding],
        exported_script_path: Optional[str] = None,
        exported_json_path: Optional[str] = None,
    ) -> None:
        """Render the Executive Summary Panel at the end of the scan."""
        metrics = self.compute_posture_metrics(findings)
        score = metrics["compliance_score_pct"]
        risk_tier = metrics["risk_tier"]

        if risk_tier == "HIGH":
            score_style = "bold red"
            border_style = "red"
            impact_text = get_text(self.lang, "impact_high")
        elif risk_tier == "MEDIUM":
            score_style = "yellow"
            border_style = "yellow"
            impact_text = get_text(self.lang, "impact_medium")
        else:
            score_style = "green"
            border_style = "green"
            impact_text = get_text(self.lang, "impact_low")

        summary_grid = Table.grid(padding=(0, 3))
        summary_grid.add_column(style="bold white")
        summary_grid.add_column(style="white")
        summary_grid.add_column(style="bold white")
        summary_grid.add_column(style="white")

        summary_grid.add_row(
            f"{get_text(self.lang, 'lbl_total_vectors')}:",
            str(metrics["total_vectors"]),
            f"{get_text(self.lang, 'lbl_critical_count')}:",
            f"[bold red]{metrics['critical_high_count']}[/bold red]" if metrics["critical_high_count"] else "[green]0[/green]",
        )
        summary_grid.add_row(
            f"{get_text(self.lang, 'lbl_compliance_score')}:",
            f"[{score_style}]{score:.1f}%[/{score_style}]",
            f"{get_text(self.lang, 'lbl_medium_count')}:",
            f"[yellow]{metrics['medium_count']}[/yellow]" if metrics["medium_count"] else "[green]0[/green]",
        )
        summary_grid.add_row(
            f"{get_text(self.lang, 'lbl_pass_count')}:",
            f"[green]{metrics['pass_count']}[/green] / {metrics['total_vectors']}",
            f"{get_text(self.lang, 'lbl_impact')}:",
            impact_text,
        )

        if exported_script_path:
            summary_grid.add_row(
                f"{get_text(self.lang, 'script_exported')}:",
                f"[cyan]{exported_script_path}[/cyan]",
                "",
                "",
            )
        if exported_json_path:
            summary_grid.add_row(
                f"{get_text(self.lang, 'json_exported')}:",
                f"[cyan]{exported_json_path}[/cyan]",
                "",
                "",
            )

        panel = Panel(
            summary_grid,
            title=f"[bold white]{get_text(self.lang, 'exec_summary_title')}[/bold white]",
            border_style=border_style,
            box=box.ROUNDED,
            padding=(0, 2),
        )
        self.console.print(panel)
        self.console.print()

    def build_json_payload(self, findings: List[AuditFinding]) -> Dict[str, Any]:
        """Build the structured JSON compliance and forensic audit report dictionary."""
        host_meta = self.get_host_metadata()
        metrics = self.compute_posture_metrics(findings)
        return {
            "metadata": host_meta,
            "executive_summary": {
                **metrics,
                "estimated_impact": (
                    get_text(self.lang, "impact_high")
                    if metrics["risk_tier"] == "HIGH"
                    else get_text(self.lang, "impact_medium")
                    if metrics["risk_tier"] == "MEDIUM"
                    else get_text(self.lang, "impact_low")
                ),
            },
            "findings": [f.to_dict() for f in findings],
        }

    def export_json_report(self, findings: List[AuditFinding], output_path: str = "audit_report.json") -> str:
        """Write the structured JSON audit report to disk and return the resolved path."""
        payload = self.build_json_payload(findings)
        target = Path(output_path).resolve()
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(target)
