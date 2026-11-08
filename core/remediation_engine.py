from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from core import AuditFinding, __version__, __repo__


BASELINE_HARDENING_BLOCKS_PS1: List[Dict[str, str]] = [
    {
        "vector_id": "REG-001",
        "title": "Disable AlwaysInstallElevated Policy (MITRE T1548.002 / CIS 18.9.85.2)",
        "code": (
            "foreach ($hive in @('HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer', 'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer')) {\n"
            "    if (-not (Test-Path $hive)) { New-Item -Path $hive -Force | Out-Null }\n"
            "    Set-ItemProperty -Path $hive -Name 'AlwaysInstallElevated' -Value 0 -Type DWord -Force\n"
            "}"
        ),
    },
    {
        "vector_id": "REG-002..004",
        "title": "Enforce User Account Control (UAC) Secure Desktop & Prompt Baseline (MITRE T1548.002 / CIS 2.3.17.x)",
        "code": (
            "$uacPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'\n"
            "Set-ItemProperty -Path $uacPath -Name 'EnableLUA' -Value 1 -Type DWord -Force\n"
            "Set-ItemProperty -Path $uacPath -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord -Force\n"
            "Set-ItemProperty -Path $uacPath -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord -Force"
        ),
    },
    {
        "vector_id": "REG-005..007",
        "title": "Enable LSASS Protected Process Light (RunAsPPL) & Disable WDigest Caching (MITRE T1003.001)",
        "code": (
            "$lsaPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'\n"
            "New-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -Value 1 -PropertyType DWord -Force | Out-Null\n"
            "$wdigestPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest'\n"
            "if (Test-Path $wdigestPath) {\n"
            "    Set-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -Value 0 -Type DWord -Force\n"
            "}"
        ),
    },
    {
        "vector_id": "ENV-003..004",
        "title": "Configure PowerShell ExecutionPolicy & ScriptBlock Logging Event ID 4104 (MITRE T1059.001)",
        "code": (
            "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force\n"
            "$sblPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'\n"
            "if (-not (Test-Path $sblPath)) { New-Item -Path $sblPath -Force | Out-Null }\n"
            "Set-ItemProperty -Path $sblPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force"
        ),
    },
]

BASELINE_HARDENING_BLOCKS_BAT: List[Dict[str, str]] = [
    {
        "vector_id": "REG-001",
        "title": "Disable AlwaysInstallElevated Policy (MITRE T1548.002 / CIS 18.9.85.2)",
        "code": (
            'reg add "HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f\n'
            'reg add "HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'
        ),
    },
    {
        "vector_id": "REG-002..004",
        "title": "Enforce User Account Control (UAC) Secure Desktop & Prompt Baseline (MITRE T1548.002 / CIS 2.3.17.x)",
        "code": (
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f\n'
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f\n'
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f'
        ),
    },
    {
        "vector_id": "REG-005..007",
        "title": "Enable LSASS Protected Process Light (RunAsPPL) & Disable WDigest Caching (MITRE T1003.001)",
        "code": (
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f\n'
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f'
        ),
    },
    {
        "vector_id": "ENV-003..004",
        "title": "Configure PowerShell ExecutionPolicy & ScriptBlock Logging Event ID 4104 (MITRE T1059.001)",
        "code": (
            'powershell -NoProfile -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"\n'
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
        ),
    },
]


class RemediationEngine:
    """Generates technical mitigation summaries and exports safe remediation scripts."""

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang.lower() if lang.lower() in ("en", "id") else "en"

    @staticmethod
    def get_actionable_findings(findings: List[AuditFinding]) -> List[AuditFinding]:
        """Return all findings that require configuration remediation (non-PASS)."""
        return [f for f in findings if f.status.upper() not in ("PASS", "INFO")]

    def export_remediation_script(
        self,
        findings: List[AuditFinding],
        script_format: str = "ps1",
        output_path: str = "",
    ) -> str:
        """
        Export an administrator-reviewable PowerShell (.ps1) or Batch (.bat) hardening script.
        Includes Registry state backup commands, privilege checks, and per-finding remediation blocks.
        """
        fmt = script_format.lower().strip()
        if fmt not in ("ps1", "bat"):
            raise ValueError(f"Unsupported remediation script format: {script_format}")

        if not output_path:
            output_path = "hardening_remediation.ps1" if fmt == "ps1" else "hardening_remediation.bat"

        target_file = Path(output_path).resolve()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        actionable = self.get_actionable_findings(findings)

        if fmt == "ps1":
            content = self._build_ps1_script(actionable, timestamp)
        else:
            content = self._build_bat_script(actionable, timestamp)

        target_file.write_text(content, encoding="utf-8")
        return str(target_file)

    def _build_ps1_script(self, actionable: List[AuditFinding], timestamp: str) -> str:
        """Construct a structured, idempotent PowerShell remediation script."""
        lines: List[str] = [
            "#Requires -RunAsAdministrator",
            "<#",
            ".SYNOPSIS",
            "    WinHardener Automated Host Hardening & LPE Remediation Script",
            ".DESCRIPTION",
            f"    Generated by WinHardener v{__version__} ({__repo__})",
            f"    Timestamp (UTC): {timestamp}",
            "    Review all configuration blocks carefully in a staging environment before execution.",
            "#>",
            "",
            "[CmdletBinding(SupportsShouldProcess=$true)]",
            "param()",
            "",
            "$ErrorActionPreference = 'Stop'",
            "Write-Host '[WinHardener] Initializing host configuration hardening workflow...' -ForegroundColor Cyan",
            "",
            "# 1. Create Registry Backup Directory",
            "$BackupDir = Join-Path $PSScriptRoot ('reg_backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))",
            "New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null",
            "Write-Host \"[WinHardener] Exporting Registry recovery checkpoints to: $BackupDir\" -ForegroundColor Gray",
            "& reg.exe export 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' (Join-Path $BackupDir 'uac_policies.reg') /y | Out-Null",
            "& reg.exe export 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' (Join-Path $BackupDir 'lsa_control.reg') /y | Out-Null",
            "",
        ]

        if actionable:
            lines.append(f"# 2. Apply Targeted Remediations for {len(actionable)} Detected Finding(s)")
            for idx, item in enumerate(actionable, start=1):
                if not item.remediation_ps1:
                    continue
                lines.extend([
                    f"# --- [{idx}] {item.vector_id}: {item.title} ({item.mitre_id} | {item.cis_ref}) ---",
                    f"# Observed: {item.current_value}",
                    f"# Expected: {item.expected_value}",
                    f"if ($PSCmdlet.ShouldProcess('{item.target}', 'Apply {item.vector_id} Remediation')) {{",
                    "    " + item.remediation_ps1.replace("\n", "\n    "),
                    f"    Write-Host '[APPLIED] {item.vector_id} - {item.title}' -ForegroundColor Green",
                    "}",
                    "",
                ])
        else:
            lines.append("# 2. Baseline Hardening Verification Blocks (All audited controls passed during scan)")
            for idx, block in enumerate(BASELINE_HARDENING_BLOCKS_PS1, start=1):
                lines.extend([
                    f"# --- [{idx}] {block['vector_id']}: {block['title']} ---",
                    f"if ($PSCmdlet.ShouldProcess('{block['vector_id']}', 'Enforce Baseline Policy')) {{",
                    "    " + block["code"].replace("\n", "\n    "),
                    f"    Write-Host '[VERIFIED] {block['vector_id']} Baseline Policy Enforced' -ForegroundColor Green",
                    "}",
                    "",
                ])

        lines.extend([
            "Write-Host '[WinHardener] Remediation workflow completed. A system reboot is required for UAC and LSA changes to take full effect.' -ForegroundColor Cyan",
            "",
        ])
        return "\n".join(lines)

    def _build_bat_script(self, actionable: List[AuditFinding], timestamp: str) -> str:
        """Construct a structured, administrator-reviewable Windows Batch remediation script."""
        lines: List[str] = [
            "@echo off",
            "REM ==========================================================================",
            "REM WinHardener Automated Host Hardening & LPE Remediation Script",
            f"REM Generated by WinHardener v{__version__} ({__repo__})",
            f"REM Timestamp (UTC): {timestamp}",
            "REM Review all configuration commands before running as Administrator.",
            "REM ==========================================================================",
            "",
            "net session >nul 2>&1",
            "if %errorLevel% neq 0 (",
            "    echo [ERROR] Administrative privileges are required to execute this remediation script.",
            "    pause",
            "    exit /b 1",
            ")",
            "",
            "echo [WinHardener] Exporting Registry backup checkpoints...",
            "if not exist \"%~dp0reg_backup\" mkdir \"%~dp0reg_backup\"",
            "reg export \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" \"%~dp0reg_backup\\uac_policies.reg\" /y >nul 2>&1",
            "reg export \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" \"%~dp0reg_backup\\lsa_control.reg\" /y >nul 2>&1",
            "",
        ]

        if actionable:
            lines.append(f"REM Apply Targeted Remediations ({len(actionable)} Finding(s))")
            for idx, item in enumerate(actionable, start=1):
                if not item.remediation_bat:
                    continue
                lines.extend([
                    f"REM --- [{idx}] {item.vector_id}: {item.title} ({item.mitre_id} / {item.cis_ref}) ---",
                    f"echo [APPLYING] {item.vector_id}: {item.title}",
                    item.remediation_bat,
                    "",
                ])
        else:
            lines.append("REM Apply Deterministic Baseline Hardening Controls")
            for idx, block in enumerate(BASELINE_HARDENING_BLOCKS_BAT, start=1):
                lines.extend([
                    f"REM --- [{idx}] {block['vector_id']}: {block['title']} ---",
                    f"echo [ENFORCING] {block['vector_id']}: {block['title']}",
                    block["code"],
                    "",
                ])

        lines.extend([
            "echo.",
            "echo [WinHardener] Remediation completed. Reboot the host to finalize UAC and LSA changes.",
            "pause",
            "",
        ])
        return "\n".join(lines)
