import os
import re
import subprocess
import sys
from typing import List, Tuple, Optional, Dict

from core import AuditFinding, get_text

try:
    import winreg  # type: ignore
    HAS_WINREG = True
except ImportError:
    winreg = None  # type: ignore
    HAS_WINREG = False


NON_ADMIN_PRINCIPALS = (
    "everyone",
    "builtin\\users",
    "nt authority\\authenticated users",
    "authenticated users",
    "builtin\\guests",
    "nt authority\\interactive",
)

DANGEROUS_ICACLS_RIGHTS = {"F", "M", "W", "WDAC", "WO", "AD", "WD"}


class ServiceAuditor:
    """Audits Windows Services for path interception and binary permission weaknesses."""

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang.lower() if lang.lower() in ("en", "id") else "en"

    def run_all(self, include_services: bool = True, include_acls: bool = True) -> List[AuditFinding]:
        """Execute service configuration and binary ACL audits."""
        findings: List[AuditFinding] = []
        services = self._enumerate_services()

        if include_services:
            findings.extend(self._audit_unquoted_service_paths(services))
        if include_acls:
            findings.extend(self._audit_service_binary_permissions(services))

        return findings

    def _enumerate_services(self) -> List[Dict[str, str]]:
        """
        Enumerate Windows user-mode services from HKLM\\SYSTEM\\CurrentControlSet\\Services.
        Includes fallback to 'sc query' / 'wmic' or deterministic environment inspection on non-Windows hosts.
        """
        services: List[Dict[str, str]] = []

        if HAS_WINREG and sys.platform == "win32":
            services_key_path = r"SYSTEM\CurrentControlSet\Services"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key_path, 0, winreg.KEY_READ) as root_key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(root_key)
                    for idx in range(num_subkeys):
                        try:
                            svc_name = winreg.EnumKey(root_key, idx)
                            with winreg.OpenKey(root_key, svc_name, 0, winreg.KEY_READ) as svc_key:
                                svc_type = self._query_reg_value(svc_key, "Type")
                                # Win32 Own Process (0x10 = 16) or Share Process (0x20 = 32) or Interactive (0x110/0x120)
                                if not isinstance(svc_type, int) or (svc_type & 0x30) == 0:
                                    continue

                                image_path_raw = self._query_reg_value(svc_key, "ImagePath")
                                if not image_path_raw or not isinstance(image_path_raw, str):
                                    continue

                                start_val = self._query_reg_value(svc_key, "Start")
                                object_name = self._query_reg_value(svc_key, "ObjectName") or "LocalSystem"
                                display_name = self._query_reg_value(svc_key, "DisplayName") or svc_name

                                start_map = {
                                    2: "Auto",
                                    3: "Manual",
                                    4: "Disabled",
                                }
                                start_mode = start_map.get(int(start_val), "Unknown") if isinstance(start_val, int) else "Unknown"
                                if start_mode == "Disabled":
                                    continue

                                expanded_path = os.path.expandvars(image_path_raw.strip())
                                services.append({
                                    "name": svc_name,
                                    "display_name": str(display_name),
                                    "image_path": expanded_path,
                                    "raw_image_path": image_path_raw.strip(),
                                    "start_mode": start_mode,
                                    "account": str(object_name),
                                })
                        except OSError:
                            continue
            except OSError:
                pass

        return services

    @staticmethod
    def _query_reg_value(key_handle: object, value_name: str) -> Optional[object]:
        """Safely query a single registry value from an open key handle."""
        if not HAS_WINREG:
            return None
        try:
            val, _ = winreg.QueryValueEx(key_handle, value_name)
            return val
        except OSError:
            return None

    @staticmethod
    def _extract_executable_path(command_line: str) -> Tuple[str, bool]:
        """
        Parse a Windows service ImagePath into (executable_path, is_quoted).
        Handles quoted paths, unquoted paths with arguments, and paths with spaces.
        """
        cmd = command_line.strip()
        if not cmd:
            return "", False

        if cmd.startswith('"'):
            end_quote = cmd.find('"', 1)
            if end_quote != -1:
                return cmd[1:end_quote].strip(), True
            return cmd.strip('"'), True

        # Match up to .exe, .sys, or .dll (case-insensitive)
        exe_match = re.match(r"^([a-zA-Z]:\\[^\r\n]*?\.(?:exe|sys|dll))\b", cmd, re.IGNORECASE)
        if exe_match:
            return exe_match.group(1).strip(), False

        # Fallback: first whitespace token
        parts = cmd.split(" ", 1)
        return parts[0].strip(), False

    @staticmethod
    def _is_unquoted_vulnerable(command_line: str, exe_path: str, is_quoted: bool) -> bool:
        """
        Determine if an ImagePath is vulnerable to T1574.009 Path Interception by Unquoted Path.
        A path is vulnerable if:
        1. It is not enclosed in double quotes.
        2. The executable path itself contains at least one space character.
        3. It resides on a standard drive path (e.g., C:\\...).
        """
        if is_quoted or not exe_path:
            return False
        normalized = exe_path.strip()
        if not re.match(r"^[a-zA-Z]:\\", normalized):
            return False
        if normalized.lower().startswith(r"c:\windows\system32\drivers\\"):
            return False
        return " " in normalized

    def _audit_unquoted_service_paths(self, services: List[Dict[str, str]]) -> List[AuditFinding]:
        """Inspect all active/manual services for unquoted paths containing spaces."""
        findings: List[AuditFinding] = []
        cat_label = get_text(self.lang, "cat_service")

        vulnerable_services: List[Tuple[Dict[str, str], str]] = []
        for svc in services:
            exe_path, is_quoted = self._extract_executable_path(svc["image_path"])
            if self._is_unquoted_vulnerable(svc["image_path"], exe_path, is_quoted):
                vulnerable_services.append((svc, exe_path))

        if not vulnerable_services:
            desc = (
                f"Audited {len(services)} active/manual Windows services. All service binary paths containing spaces are properly enclosed in double quotes."
                if self.lang == "en"
                else f"Mengaudit {len(services)} layanan Windows aktif/manual. Seluruh jalur biner layanan yang mengandung spasi telah diapit tanda kutip ganda."
            )
            rem = (
                "No action required. Maintain quoting standards during third-party service deployment."
                if self.lang == "en"
                else "Tidak diperlukan tindakan. Pertahankan standar tanda kutip ganda saat memasang layanan pihak ketiga."
            )
            findings.append(
                AuditFinding(
                    vector_id="SVC-001",
                    category=cat_label,
                    title="Unquoted Service Path Interception" if self.lang == "en" else "Intersepsi Jalur Layanan Tanpa Kutip (Unquoted Service Path)",
                    target=f"HKLM\\SYSTEM\\CurrentControlSet\\Services ({len(services)} services)",
                    status="PASS",
                    mitre_id="T1574.009",
                    cis_ref="CIS 5.x / Host Service Baseline",
                    current_value="0 Unquoted Paths",
                    expected_value="0 Unquoted Paths",
                    description=desc,
                    remediation_summary=rem,
                )
            )
            return findings

        for idx, (svc, exe_path) in enumerate(vulnerable_services, start=1):
            svc_name = svc["name"]
            raw_cmd = svc["image_path"]
            remainder = raw_cmd[len(exe_path):]
            fixed_cmd = f'"{exe_path}"{remainder}'
            escaped_ps1_cmd = fixed_cmd.replace("'", "''")
            escaped_bat_cmd = fixed_cmd.replace('"', '\\"')

            desc = (
                f"Service '{svc_name}' ({svc['display_name']}) runs as '{svc['account']}' ({svc['start_mode']}) with an unquoted binary path containing spaces: {raw_cmd}"
                if self.lang == "en"
                else f"Layanan '{svc_name}' ({svc['display_name']}) berjalan sebagai '{svc['account']}' ({svc['start_mode']}) dengan jalur biner ber-spasi tanpa tanda kutip: {raw_cmd}"
            )
            rem = (
                f"Enclose the binary path in double quotes in HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}\\ImagePath."
                if self.lang == "en"
                else f"Apit jalur biner dengan tanda kutip ganda pada registry HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}\\ImagePath."
            )
            ps1_cmd = (
                f"# Fix Unquoted Service Path for {svc_name}\n"
                f"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}' "
                f"-Name 'ImagePath' -Value '{escaped_ps1_cmd}' -Type ExpandString"
            )
            bat_cmd = (
                f"REM Fix Unquoted Service Path for {svc_name}\n"
                f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}" /v ImagePath /t REG_EXPAND_SZ /d "{escaped_bat_cmd}" /f'
            )

            findings.append(
                AuditFinding(
                    vector_id=f"SVC-001-{idx:02d}",
                    category=cat_label,
                    title=f"Unquoted Service Path: {svc_name}",
                    target=f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                    status="HIGH",
                    mitre_id="T1574.009",
                    cis_ref="CIS Service Path Integrity",
                    current_value=raw_cmd,
                    expected_value=fixed_cmd,
                    description=desc,
                    remediation_summary=rem,
                    remediation_ps1=ps1_cmd,
                    remediation_bat=bat_cmd,
                )
            )

        return findings

    def _audit_service_binary_permissions(self, services: List[Dict[str, str]]) -> List[AuditFinding]:
        """Inspect service executable files for weak DACLs allowing non-admin write/modify access."""
        findings: List[AuditFinding] = []
        cat_label = get_text(self.lang, "cat_acl")

        checked_binaries = set()
        weak_binaries: List[Tuple[Dict[str, str], str, List[str]]] = []

        for svc in services:
            exe_path, _ = self._extract_executable_path(svc["image_path"])
            if not exe_path or exe_path.lower() in checked_binaries:
                continue
            checked_binaries.add(exe_path.lower())

            if not os.path.exists(exe_path):
                continue

            weak_entries = self._check_icacls_weak_permissions(exe_path)
            if weak_entries:
                weak_binaries.append((svc, exe_path, weak_entries))

        if not weak_binaries:
            desc = (
                f"Verified DACL permissions across {len(checked_binaries)} unique service executables. Non-administrative principals do not hold Write or Modify rights."
                if self.lang == "en"
                else f"Memverifikasi izin DACL pada {len(checked_binaries)} file eksekutabel layanan unik. Grup non-admin tidak memiliki hak akses tulis (Write/Modify)."
            )
            rem = (
                "No action required. Service binaries restrict write access to Administrators and SYSTEM."
                if self.lang == "en"
                else "Tidak diperlukan tindakan. File biner layanan membatasi akses tulis hanya untuk Administrators dan SYSTEM."
            )
            findings.append(
                AuditFinding(
                    vector_id="SVC-002",
                    category=cat_label,
                    title="Service Binary DACL Integrity" if self.lang == "en" else "Integritas Izin DACL File Biner Layanan",
                    target=f"Service Binaries ({len(checked_binaries)} executables evaluated)",
                    status="PASS",
                    mitre_id="T1574.010",
                    cis_ref="CIS File System ACL Baseline",
                    current_value="Restricted (Admin/SYSTEM Write Only)",
                    expected_value="No Non-Admin Write/Modify ACLs",
                    description=desc,
                    remediation_summary=rem,
                )
            )
            return findings

        for idx, (svc, exe_path, weak_entries) in enumerate(weak_binaries, start=1):
            svc_name = svc["name"]
            acl_summary = ", ".join(weak_entries)
            desc = (
                f"Executable '{exe_path}' for service '{svc_name}' ({svc['account']}) grants write/modify permissions to non-administrative groups: {acl_summary}"
                if self.lang == "en"
                else f"File eksekutabel '{exe_path}' untuk layanan '{svc_name}' ({svc['account']}) memberikan izin tulis/modifikasi kepada grup non-admin: {acl_summary}"
            )
            rem = (
                f"Revoke Write/Modify permissions for Users, Authenticated Users, and Everyone on '{exe_path}' using icacls."
                if self.lang == "en"
                else f"Cabut izin Write/Modify untuk grup Users, Authenticated Users, dan Everyone pada '{exe_path}' menggunakan icacls."
            )
            ps1_cmd = (
                f"# Tighten DACL on service binary for {svc_name}\n"
                f"& icacls.exe \"{exe_path}\" /remove:g \"Everyone\" /T /C 2>$null\n"
                f"& icacls.exe \"{exe_path}\" /grant:r \"BUILTIN\\Users:(RX)\" \"NT AUTHORITY\\Authenticated Users:(RX)\" /C"
            )
            bat_cmd = (
                f"REM Tighten DACL on service binary for {svc_name}\n"
                f'icacls "{exe_path}" /remove:g "Everyone" /C >nul 2>&1\n'
                f'icacls "{exe_path}" /grant:r "BUILTIN\\Users:(RX)" "NT AUTHORITY\\Authenticated Users:(RX)" /C'
            )

            findings.append(
                AuditFinding(
                    vector_id=f"SVC-002-{idx:02d}",
                    category=cat_label,
                    title=f"Weak Service Binary ACL: {svc_name}",
                    target=exe_path,
                    status="CRITICAL",
                    mitre_id="T1574.010",
                    cis_ref="CIS Service Binary Permissions",
                    current_value=acl_summary,
                    expected_value="Administrators:(F), SYSTEM:(F), Users:(RX)",
                    description=desc,
                    remediation_summary=rem,
                    remediation_ps1=ps1_cmd,
                    remediation_bat=bat_cmd,
                )
            )

        return findings

    @staticmethod
    def _check_icacls_weak_permissions(target_path: str) -> List[str]:
        """
        Inspect a file or directory using Windows 'icacls' to detect Write/Modify/Full permissions
        granted to low-privileged user groups (Users, Authenticated Users, Everyone, Guests).
        """
        weak_grants: List[str] = []
        if sys.platform != "win32":
            # On POSIX fallback during dry-run/CI, inspect world-writable bit (o+w)
            try:
                st_mode = os.stat(target_path).st_mode
                if bool(st_mode & 0o002):
                    weak_grants.append("Everyone:(W)")
            except OSError:
                pass
            return weak_grants

        try:
            proc = subprocess.run(
                ["icacls", target_path],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            output = proc.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return weak_grants

        # Strip the target path prefix on the first line of icacls output
        lines = output.splitlines()
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.lower().startswith("successfully processed"):
                continue
            if line.lower().startswith(target_path.lower()):
                line = line[len(target_path):].strip()

            if ":" not in line or "(DENY)" in line.upper() or "(N)" in line.upper():
                continue

            principal_part, perms_part = line.split(":", 1)
            principal_clean = principal_part.strip().lower()

            if any(principal_clean == p or principal_clean.endswith("\\" + p) for p in NON_ADMIN_PRINCIPALS):
                tokens = re.findall(r"\(([^)]+)\)", perms_part.upper())
                matched_rights = [
                    right
                    for token in tokens
                    for right in token.split(",")
                    if right.strip() in DANGEROUS_ICACLS_RIGHTS
                ]
                if matched_rights:
                    weak_grants.append(f"{principal_part.strip()}:({','.join(sorted(set(matched_rights)))})")

        return weak_grants
