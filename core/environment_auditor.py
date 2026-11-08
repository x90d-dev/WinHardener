import os
import sys
from typing import List, Optional, Tuple

from core import AuditFinding, get_text
from core.service_auditor import ServiceAuditor

try:
    import winreg  # type: ignore
    HAS_WINREG = True
except ImportError:
    winreg = None  # type: ignore
    HAS_WINREG = False


class EnvironmentAuditor:

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang.lower() if lang.lower() in ("en", "id") else "en"

    def run_all(self, include_acls: bool = True, include_registry: bool = True) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if include_acls:
            findings.extend(self._audit_system_path_acls())
        if include_registry:
            findings.extend(self._audit_powershell_posture())
        return findings

    def _get_system_path_entries(self) -> List[str]:
        raw_path = ""
        if HAS_WINREG and sys.platform == "win32":
            env_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, env_key, 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, "Path")
                    if isinstance(val, str):
                        raw_path = val
            except OSError:
                raw_path = os.environ.get("PATH", "")
        else:
            raw_path = os.environ.get("PATH", "")

        entries: List[str] = []
        seen = set()
        for item in raw_path.split(os.pathsep):
            cleaned = os.path.expandvars(item.strip().strip('"'))
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                entries.append(cleaned)
        return entries

    def _audit_system_path_acls(self) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        cat_label = get_text(self.lang, "cat_acl")
        path_dirs = self._get_system_path_entries()

        writable_dirs: List[Tuple[str, List[str]]] = []
        missing_dirs: List[str] = []

        for directory in path_dirs:
            if not os.path.exists(directory):
                missing_dirs.append(directory)
                continue

            weak_grants = ServiceAuditor._check_icacls_weak_permissions(directory)
            if weak_grants:
                writable_dirs.append((directory, weak_grants))

        if not writable_dirs:
            desc = (
                f"Evaluated {len(path_dirs)} system PATH directories. No directories grant Write or Modify permissions to standard user groups."
                if self.lang == "en"
                else f"Mengevaluasi {len(path_dirs)} direktori pada variabel PATH sistem. Tidak ada direktori yang memberikan izin tulis (Write/Modify) kepada grup pengguna biasa."
            )
            rem = (
                "No action required. System PATH directories restrict modification rights to privileged accounts."
                if self.lang == "en"
                else "Tidak diperlukan tindakan. Direktori PATH sistem membatasi hak modifikasi hanya untuk akun berprivilese."
            )
            findings.append(
                AuditFinding(
                    vector_id="ENV-001",
                    category=cat_label,
                    title="System PATH Directory ACL Integrity" if self.lang == "en" else "Integritas Izin ACL Direktori PATH Sistem",
                    target=f"System PATH ({len(path_dirs)} directories)",
                    status="PASS",
                    mitre_id="T1574.007",
                    cis_ref="CIS Environment PATH Integrity",
                    current_value="0 Non-Admin Writable Directories",
                    expected_value="0 Non-Admin Writable Directories",
                    description=desc,
                    remediation_summary=rem,
                )
            )
        else:
            for idx, (directory, grants) in enumerate(writable_dirs, start=1):
                grant_str = ", ".join(grants)
                desc = (
                    f"System PATH directory '{directory}' grants write/modify access to non-administrative groups ({grant_str}), enabling DLL search order hijacking or binary interception."
                    if self.lang == "en"
                    else f"Direktori PATH sistem '{directory}' memberikan akses tulis/modifikasi kepada grup non-admin ({grant_str}), membuka celah DLL Hijacking atau intersepsi biner."
                )
                rem = (
                    f"Remove Write/Modify permissions for non-administrative groups on '{directory}' using icacls."
                    if self.lang == "en"
                    else f"Cabut izin Write/Modify untuk grup non-admin pada direktori '{directory}' menggunakan icacls."
                )
                ps1_cmd = (
                    f"# Remove non-admin write permissions on system PATH directory: {directory}\n"
                    f"& icacls.exe \"{directory}\" /remove:g \"Everyone\" /C 2>$null\n"
                    f"& icacls.exe \"{directory}\" /grant:r \"BUILTIN\\Users:(OI)(CI)(RX)\" \"NT AUTHORITY\\Authenticated Users:(OI)(CI)(RX)\" /C"
                )
                bat_cmd = (
                    f"REM Remove non-admin write permissions on system PATH directory: {directory}\n"
                    f'icacls "{directory}" /remove:g "Everyone" /C >nul 2>&1\n'
                    f'icacls "{directory}" /grant:r "BUILTIN\\Users:(OI)(CI)(RX)" "NT AUTHORITY\\Authenticated Users:(OI)(CI)(RX)" /C'
                )
                findings.append(
                    AuditFinding(
                        vector_id=f"ENV-001-{idx:02d}",
                        category=cat_label,
                        title=f"Writable System PATH Directory: {os.path.basename(directory) or directory}",
                        target=directory,
                        status="HIGH",
                        mitre_id="T1574.007",
                        cis_ref="CIS Environment PATH Integrity",
                        current_value=grant_str,
                        expected_value="Administrators:(F), SYSTEM:(F), Users:(RX)",
                        description=desc,
                        remediation_summary=rem,
                        remediation_ps1=ps1_cmd,
                        remediation_bat=bat_cmd,
                    )
                )

        if missing_dirs:
            joined_missing = "; ".join(missing_dirs[:3])
            if len(missing_dirs) > 3:
                joined_missing += f" (+{len(missing_dirs) - 3} more)"
            findings.append(
                AuditFinding(
                    vector_id="ENV-002",
                    category=cat_label,
                    title="Orphaned / Non-Existent System PATH Entries" if self.lang == "en" else "Entri Direktori PATH Sistem Tidak Ditemukan (Orphaned)",
                    target="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path",
                    status="MEDIUM",
                    mitre_id="T1574.007",
                    cis_ref="CIS Environment Hygiene",
                    current_value=f"{len(missing_dirs)} orphaned path(s): {joined_missing}",
                    expected_value="All system PATH directories exist on disk",
                    description=(
                        f"Found {len(missing_dirs)} non-existent directory entry(s) in system PATH ({joined_missing}). If a low-privileged user can create the missing folder in its parent directory, they can plant rogue DLLs."
                        if self.lang == "en"
                        else f"Ditemukan {len(missing_dirs)} entri direktori pada PATH sistem yang tidak ada di disk ({joined_missing}). Jika pengguna standar dapat membuat kembali folder tersebut, celah penanaman DLL dapat terjadi."
                    ),
                    remediation_summary=(
                        "Prune non-existent directory entries from HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path."
                        if self.lang == "en"
                        else "Hapus entri direktori yang sudah tidak ada dari variabel Path pada HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment."
                    ),
                    remediation_ps1=(
                        "# Prune non-existent directories from System PATH\n"
                        "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'\n"
                        "$currentPath = (Get-ItemProperty -Path $regPath -Name 'Path').Path\n"
                        "$cleanDirs = ($currentPath -split ';') | Where-Object { $_ -and (Test-Path $_) }\n"
                        "Set-ItemProperty -Path $regPath -Name 'Path' -Value ($cleanDirs -join ';')"
                    ),
                    remediation_bat=(
                        "REM Review and prune orphaned directories from System PATH via powershell\n"
                        "powershell -NoProfile -Command \"$r='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'; $p=(Get-ItemProperty $r -Name Path).Path; $c=($p -split ';')|?{$_ -and (Test-Path $_)}; Set-ItemProperty $r -Name Path -Value ($c -join ';')\""
                    ),
                )
            )

        return findings

    def _audit_powershell_posture(self) -> List[AuditFinding]:
        """
        Audit PowerShell Execution Policy and ScriptBlock Logging (MITRE T1059.001 / CIS 18.9.95.x).
        """
        findings: List[AuditFinding] = []
        cat_label = get_text(self.lang, "cat_powershell")

        exec_policy = self._read_powershell_execution_policy()
        secure_policies = {"restricted", "allsigned", "remotesigned"}
        pol_pass = exec_policy.lower() in secure_policies

        findings.append(
            AuditFinding(
                vector_id="ENV-003",
                category=cat_label,
                title="PowerShell Execution Policy Baseline" if self.lang == "en" else "Kebijakan Eksekusi Skrip PowerShell (Execution Policy)",
                target=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy",
                status="PASS" if pol_pass else "MEDIUM",
                mitre_id="T1059.001",
                cis_ref="CIS 18.9.95.x (PowerShell Execution)",
                current_value=f"ExecutionPolicy={exec_policy}",
                expected_value="RemoteSigned or AllSigned",
                description=(
                    f"PowerShell Execution Policy is configured to '{exec_policy}', preventing accidental execution of unsigned remote scripts."
                    if pol_pass and self.lang == "en"
                    else f"Execution Policy PowerShell diatur ke '{exec_policy}', membatasi eksekusi skrip jarak jauh tanpa tanda tangan digital."
                    if pol_pass
                    else f"PowerShell Execution Policy is set to '{exec_policy}'. Unrestricted or Bypass policies allow unsigned scripts to run without baseline validation."
                    if self.lang == "en"
                    else f"Execution Policy PowerShell bernilai '{exec_policy}'. Kebijakan Unrestricted atau Bypass mengizinkan skrip tanpa tanda tangan berjalan bebas."
                ),
                remediation_summary=(
                    "Set LocalMachine PowerShell ExecutionPolicy to 'RemoteSigned' or 'AllSigned'."
                    if self.lang == "en"
                    else "Atur ExecutionPolicy PowerShell tingkat LocalMachine ke 'RemoteSigned' atau 'AllSigned'."
                ),
                remediation_ps1=(
                    ""
                    if pol_pass
                    else "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"
                ),
                remediation_bat=(
                    ""
                    if pol_pass
                    else 'powershell -NoProfile -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"'
                ),
            )
        )

        # ScriptBlock Logging (Event ID 4104)
        sbl_enabled = self._read_scriptblock_logging()
        sbl_pass = sbl_enabled == 1
        sbl_key = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

        findings.append(
            AuditFinding(
                vector_id="ENV-004",
                category=cat_label,
                title="PowerShell ScriptBlock Logging (Event ID 4104)" if self.lang == "en" else "Pencatatan Log Blok Skrip PowerShell (ScriptBlock Logging)",
                target=f"HKLM\\{sbl_key}\\EnableScriptBlockLogging",
                status="PASS" if sbl_pass else "MEDIUM",
                mitre_id="T1059.001",
                cis_ref="CIS 18.9.95.1 (L1)",
                current_value=f"EnableScriptBlockLogging={sbl_enabled if sbl_enabled is not None else '0 (Not Configured)'}",
                expected_value="EnableScriptBlockLogging=1 (Enabled)",
                description=(
                    "PowerShell ScriptBlock Logging (Event ID 4104) is enabled, capturing de-obfuscated script blocks in the Microsoft-Windows-PowerShell/Operational log."
                    if sbl_pass and self.lang == "en"
                    else "PowerShell ScriptBlock Logging (Event ID 4104) aktif, mencatat isi blok skrip secara lengkap ke dalam log operasional untuk audit forensik."
                    if sbl_pass
                    else "PowerShell ScriptBlock Logging is disabled (0 or not configured). Obfuscated or in-memory PowerShell execution will not generate Event ID 4104 telemetry."
                    if self.lang == "en"
                    else "PowerShell ScriptBlock Logging belum diaktifkan (0 atau belum dikonfigurasi). Eksekusi skrip PowerShell di memori tidak tercatat pada telemetri Event ID 4104."
                ),
                remediation_summary=(
                    "Enable EnableScriptBlockLogging=1 (DWORD) under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging."
                    if self.lang == "en"
                    else "Aktifkan EnableScriptBlockLogging=1 (DWORD) pada HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging."
                ),
                remediation_ps1=(
                    ""
                    if sbl_pass
                    else (
                        f"if (-not (Test-Path 'HKLM:\\{sbl_key}')) {{ New-Item -Path 'HKLM:\\{sbl_key}' -Force | Out-Null }}\n"
                        f"Set-ItemProperty -Path 'HKLM:\\{sbl_key}' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force"
                    )
                ),
                remediation_bat=(
                    ""
                    if sbl_pass
                    else f'reg add "HKLM\\{sbl_key}" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
                ),
            )
        )

        return findings

    @staticmethod
    def _read_powershell_execution_policy() -> str:
        """Read the LocalMachine PowerShell Execution Policy from Registry."""
        if not HAS_WINREG or sys.platform != "win32":
            return "RemoteSigned"

        policy_keys = [
            (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy"),
            (r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy"),
        ]
        for subkey, val_name in policy_keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    val, _ = winreg.QueryValueEx(key, val_name)
                    if isinstance(val, str) and val.strip():
                        return val.strip()
            except OSError:
                continue
        return "Restricted"

    @staticmethod
    def _read_scriptblock_logging() -> Optional[int]:
        """Read EnableScriptBlockLogging DWORD from HKLM."""
        if not HAS_WINREG or sys.platform != "win32":
            return 1

        sbl_key = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sbl_key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                val, _ = winreg.QueryValueEx(key, "EnableScriptBlockLogging")
                return int(val)
        except (OSError, ValueError):
            return None
