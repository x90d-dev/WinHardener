import sys
from typing import List, Optional, Tuple

from core import AuditFinding, get_text

try:
    import winreg  # type: ignore
    HAS_WINREG = True
except ImportError:
    winreg = None  # type: ignore
    HAS_WINREG = False


class RegistryAuditor:
    """Evaluates Windows Registry elevation and credential protection controls."""

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang.lower() if lang.lower() in ("en", "id") else "en"

    def run_all(self) -> List[AuditFinding]:
        """Execute all registry security posture checks."""
        findings: List[AuditFinding] = []
        findings.append(self._audit_always_install_elevated())
        findings.extend(self._audit_uac_configuration())
        findings.extend(self._audit_lsa_and_credential_guard())
        return findings

    @staticmethod
    def _read_dword(hive_name: str, subkey: str, value_name: str, default_on_non_win: Optional[int] = None) -> Optional[int]:
        """Read a REG_DWORD value from HKLM or HKCU safely."""
        if not HAS_WINREG or sys.platform != "win32":
            return default_on_non_win

        hive = winreg.HKEY_LOCAL_MACHINE if hive_name.upper() == "HKLM" else winreg.HKEY_CURRENT_USER
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                val, _ = winreg.QueryValueEx(key, value_name)
                if isinstance(val, int):
                    return val
                return int(val)
        except (OSError, ValueError):
            return None

    def _audit_always_install_elevated(self) -> AuditFinding:
        """
        Check HKLM and HKCU Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated.
        If both or either are set to 1, standard users may execute MSI packages with SYSTEM privileges.
        """
        cat_label = get_text(self.lang, "cat_registry")
        subkey = r"Software\Policies\Microsoft\Windows\Installer"
        hklm_val = self._read_dword("HKLM", subkey, "AlwaysInstallElevated", default_on_non_win=0)
        hkcu_val = self._read_dword("HKCU", subkey, "AlwaysInstallElevated", default_on_non_win=0)

        hklm_state = 1 if hklm_val == 1 else 0
        hkcu_state = 1 if hkcu_val == 1 else 0

        if hklm_state == 1 and hkcu_state == 1:
            status = "CRITICAL"
            desc = (
                "AlwaysInstallElevated is set to 1 in both HKLM and HKCU. Any standard user can execute Windows Installer (.msi) packages with NT AUTHORITY\\SYSTEM privileges."
                if self.lang == "en"
                else "AlwaysInstallElevated bernilai 1 pada HKLM dan HKCU. Pengguna standar dapat menjalankan paket Windows Installer (.msi) dengan hak akses NT AUTHORITY\\SYSTEM."
            )
        elif hklm_state == 1 or hkcu_state == 1:
            status = "MEDIUM"
            desc = (
                f"AlwaysInstallElevated is partially enabled (HKLM={hklm_state}, HKCU={hkcu_state}). Policy should be explicitly disabled (0) across both hives."
                if self.lang == "en"
                else f"AlwaysInstallElevated aktif sebagian (HKLM={hklm_state}, HKCU={hkcu_state}). Kebijakan ini harus dinonaktifkan (0) pada kedua hive."
            )
        else:
            status = "PASS"
            desc = (
                "AlwaysInstallElevated policy is disabled or not configured in HKLM and HKCU. Standard users cannot auto-elevate MSI installations."
                if self.lang == "en"
                else "Kebijakan AlwaysInstallElevated nonaktif pada HKLM dan HKCU. Pengguna standar tidak dapat melakukan elevasi otomatis melalui paket MSI."
            )

        rem = (
            "Set AlwaysInstallElevated to 0 (DWORD) or remove the value under HKLM and HKCU Installer policy keys."
            if self.lang == "en"
            else "Atur nilai DWORD AlwaysInstallElevated menjadi 0 pada kunci kebijakan Installer di HKLM dan HKCU."
        )

        ps1_cmd = ""
        bat_cmd = ""
        if status != "PASS":
            ps1_cmd = (
                "# Disable AlwaysInstallElevated in HKLM and HKCU\n"
                "foreach ($hive in @('HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer', 'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer')) {\n"
                "    if (Test-Path $hive) {\n"
                "        Set-ItemProperty -Path $hive -Name 'AlwaysInstallElevated' -Value 0 -Type DWord -Force\n"
                "    }\n"
                "}"
            )
            bat_cmd = (
                "REM Disable AlwaysInstallElevated in HKLM and HKCU\n"
                'reg add "HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f\n'
                'reg add "HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'
            )

        return AuditFinding(
            vector_id="REG-001",
            category=cat_label,
            title="AlwaysInstallElevated MSI Policy" if self.lang == "en" else "Kebijakan MSI AlwaysInstallElevated",
            target=r"HKLM & HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated",
            status=status,
            mitre_id="T1548.002",
            cis_ref="CIS 18.9.85.2 (L1)",
            current_value=f"HKLM={hklm_val if hklm_val is not None else 'Not Set (0)'}, HKCU={hkcu_val if hkcu_val is not None else 'Not Set (0)'}",
            expected_value="HKLM=0, HKCU=0 (Disabled)",
            description=desc,
            remediation_summary=rem,
            remediation_ps1=ps1_cmd,
            remediation_bat=bat_cmd,
        )

    def _audit_uac_configuration(self) -> List[AuditFinding]:
        """
        Audit User Account Control (UAC) registry values under
        HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System:
        - EnableLUA (CIS 2.3.17.8: Expected 1)
        - ConsentPromptBehaviorAdmin (CIS 2.3.17.2: Expected 1 or 2; 0 is High Risk, 5 is Default/Medium)
        - PromptOnSecureDesktop (CIS 2.3.17.7: Expected 1)
        """
        findings: List[AuditFinding] = []
        cat_label = get_text(self.lang, "cat_registry")
        uac_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        # 1. EnableLUA
        enable_lua = self._read_dword("HKLM", uac_key, "EnableLUA", default_on_non_win=1)
        lua_pass = enable_lua == 1
        findings.append(
            AuditFinding(
                vector_id="REG-002",
                category=cat_label,
                title="UAC Admin Approval Mode (EnableLUA)" if self.lang == "en" else "Mode Persetujuan Admin UAC (EnableLUA)",
                target=f"HKLM\\{uac_key}\\EnableLUA",
                status="PASS" if lua_pass else "CRITICAL",
                mitre_id="T1548.002",
                cis_ref="CIS 2.3.17.8 (L1)",
                current_value=f"EnableLUA={enable_lua if enable_lua is not None else 'Not Set'}",
                expected_value="EnableLUA=1 (Enabled)",
                description=(
                    "User Account Control (EnableLUA) is active, enforcing token filtering for administrative accounts."
                    if lua_pass and self.lang == "en"
                    else "User Account Control (EnableLUA) aktif, menerapkan pemfilteran token akses untuk akun administrator."
                    if lua_pass
                    else "User Account Control (EnableLUA) is disabled (0). Administrative processes execute with full tokens without elevation boundaries."
                    if self.lang == "en"
                    else "User Account Control (EnableLUA) dinonaktifkan (0). Proses administratif berjalan tanpa batas isolasi token."
                ),
                remediation_summary=(
                    "Set EnableLUA to 1 under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System (requires reboot)."
                    if self.lang == "en"
                    else "Atur EnableLUA menjadi 1 pada HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System (memerlukan mulai ulang sistem)."
                ),
                remediation_ps1=(
                    ""
                    if lua_pass
                    else f"Set-ItemProperty -Path 'HKLM:\\{uac_key}' -Name 'EnableLUA' -Value 1 -Type DWord -Force"
                ),
                remediation_bat=(
                    ""
                    if lua_pass
                    else f'reg add "HKLM\\{uac_key}" /v EnableLUA /t REG_DWORD /d 1 /f'
                ),
            )
        )

        # 2. ConsentPromptBehaviorAdmin
        consent_admin = self._read_dword("HKLM", uac_key, "ConsentPromptBehaviorAdmin", default_on_non_win=2)
        if consent_admin in (1, 2):
            c_status = "PASS"
            c_desc = (
                f"ConsentPromptBehaviorAdmin is set to {consent_admin} (Prompt for consent/credentials on all elevation operations, preventing silent auto-elevation bypasses)."
                if self.lang == "en"
                else f"ConsentPromptBehaviorAdmin bernilai {consent_admin} (Meminta persetujuan/kredensial pada seluruh operasi elevasi, memitigasi bypass auto-elevate)."
            )
        elif consent_admin == 5:
            c_status = "MEDIUM"
            c_desc = (
                "ConsentPromptBehaviorAdmin is set to 5 (Prompt for non-Windows binaries only). Auto-elevated Windows binaries remain susceptible to UAC bypass techniques (T1548.002)."
                if self.lang == "en"
                else "ConsentPromptBehaviorAdmin bernilai 5 (Hanya meminta konfirmasi untuk biner non-Windows). Biner bawaan Windows yang memiliki auto-elevate rentan terhadap teknik UAC bypass (T1548.002)."
            )
        else:
            c_status = "HIGH"
            c_desc = (
                f"ConsentPromptBehaviorAdmin is set to {consent_admin} (Elevate without prompting). Any administrative process can silently elevate to high integrity."
                if self.lang == "en"
                else f"ConsentPromptBehaviorAdmin bernilai {consent_admin} (Elevasi tanpa konfirmasi). Proses pada sesi admin dapat meningkatkan hak akses secara diam-diam."
            )

        findings.append(
            AuditFinding(
                vector_id="REG-003",
                category=cat_label,
                title="UAC Admin Elevation Prompt Behavior" if self.lang == "en" else "Perilaku Konfirmasi Elevasi Admin UAC",
                target=f"HKLM\\{uac_key}\\ConsentPromptBehaviorAdmin",
                status=c_status,
                mitre_id="T1548.002",
                cis_ref="CIS 2.3.17.2 (L1)",
                current_value=f"ConsentPromptBehaviorAdmin={consent_admin if consent_admin is not None else 'Not Set'}",
                expected_value="1 (Prompt for credentials) or 2 (Prompt for consent on secure desktop)",
                description=c_desc,
                remediation_summary=(
                    "Set ConsentPromptBehaviorAdmin to 2 (Prompt for consent on the secure desktop) to mitigate auto-elevated binary UAC bypasses."
                    if self.lang == "en"
                    else "Atur ConsentPromptBehaviorAdmin menjadi 2 (Minta persetujuan pada secure desktop) untuk memitigasi UAC bypass."
                ),
                remediation_ps1=(
                    ""
                    if c_status == "PASS"
                    else f"Set-ItemProperty -Path 'HKLM:\\{uac_key}' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord -Force"
                ),
                remediation_bat=(
                    ""
                    if c_status == "PASS"
                    else f'reg add "HKLM\\{uac_key}" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f'
                ),
            )
        )

        # 3. PromptOnSecureDesktop
        secure_desktop = self._read_dword("HKLM", uac_key, "PromptOnSecureDesktop", default_on_non_win=1)
        sd_pass = secure_desktop == 1
        findings.append(
            AuditFinding(
                vector_id="REG-004",
                category=cat_label,
                title="UAC Secure Desktop Isolation (PromptOnSecureDesktop)" if self.lang == "en" else "Isolasi Secure Desktop UAC (PromptOnSecureDesktop)",
                target=f"HKLM\\{uac_key}\\PromptOnSecureDesktop",
                status="PASS" if sd_pass else "MEDIUM",
                mitre_id="T1548.002",
                cis_ref="CIS 2.3.17.7 (L1)",
                current_value=f"PromptOnSecureDesktop={secure_desktop if secure_desktop is not None else 'Not Set'}",
                expected_value="PromptOnSecureDesktop=1 (Enabled)",
                description=(
                    "Elevation prompts are isolated on the Windows Secure Desktop, preventing UI spoofing or message-pumping from medium-integrity processes."
                    if sd_pass and self.lang == "en"
                    else "Dialog elevasi diisolasi pada Secure Desktop Windows, mencegah manipulasi antarmuka (UI spoofing) oleh proses berintegritas menengah."
                    if sd_pass
                    else "PromptOnSecureDesktop is disabled (0). Medium-integrity processes in the user session could interact with or spoof elevation dialog windows."
                    if self.lang == "en"
                    else "PromptOnSecureDesktop dinonaktifkan (0). Proses berintegritas menengah pada sesi pengguna berpotensi memanipulasi jendela dialog elevasi."
                ),
                remediation_summary=(
                    "Set PromptOnSecureDesktop to 1 under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System."
                    if self.lang == "en"
                    else "Atur PromptOnSecureDesktop menjadi 1 pada HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System."
                ),
                remediation_ps1=(
                    ""
                    if sd_pass
                    else f"Set-ItemProperty -Path 'HKLM:\\{uac_key}' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord -Force"
                ),
                remediation_bat=(
                    ""
                    if sd_pass
                    else f'reg add "HKLM\\{uac_key}" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f'
                ),
            )
        )

        return findings

    def _audit_lsa_and_credential_guard(self) -> List[AuditFinding]:
        """
        Audit LSA Protection (RunAsPPL) and Credential Guard (LsaCfgFlags) to mitigate
        LSASS memory credential dumping (MITRE T1003.001).
        """
        findings: List[AuditFinding] = []
        cat_label = get_text(self.lang, "cat_registry")

        lsa_key = r"SYSTEM\CurrentControlSet\Control\Lsa"
        dg_key = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
        wdigest_key = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

        # 1. RunAsPPL (Protected Process Light for LSASS)
        run_as_ppl = self._read_dword("HKLM", lsa_key, "RunAsPPL", default_on_non_win=1)
        ppl_pass = run_as_ppl in (1, 2)
        findings.append(
            AuditFinding(
                vector_id="REG-005",
                category=cat_label,
                title="LSASS Protected Process Light (RunAsPPL)" if self.lang == "en" else "Proteksi Memori LSASS (RunAsPPL)",
                target=f"HKLM\\{lsa_key}\\RunAsPPL",
                status="PASS" if ppl_pass else "HIGH",
                mitre_id="T1003.001",
                cis_ref="CIS 18.4.x / LSA Protection",
                current_value=f"RunAsPPL={run_as_ppl if run_as_ppl is not None else '0 (Not Configured)'}",
                expected_value="RunAsPPL=1 (UEFI Locked) or 2 (Enabled without UEFI Lock)",
                description=(
                    f"LSASS runs as a Protected Process Light (RunAsPPL={run_as_ppl}), blocking non-protected user-mode processes from opening PROCESS_VM_READ handles to lsass.exe."
                    if ppl_pass and self.lang == "en"
                    else f"LSASS berjalan dengan proteksi Protected Process Light (RunAsPPL={run_as_ppl}), memblokir proses non-terproteksi dari membaca memori lsass.exe."
                    if ppl_pass
                    else "RunAsPPL is not enabled (0 or missing). Administrative user-mode processes can read LSASS process memory directly (MITRE T1003.001)."
                    if self.lang == "en"
                    else "RunAsPPL belum diaktifkan (0 atau tidak ditemukan). Proses user-mode dengan hak admin dapat membaca memori proses LSASS secara langsung (MITRE T1003.001)."
                ),
                remediation_summary=(
                    "Enable LSA Protection by setting RunAsPPL=1 (DWORD) in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa."
                    if self.lang == "en"
                    else "Aktifkan LSA Protection dengan mengatur RunAsPPL=1 (DWORD) pada HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa."
                ),
                remediation_ps1=(
                    ""
                    if ppl_pass
                    else f"New-ItemProperty -Path 'HKLM:\\{lsa_key}' -Name 'RunAsPPL' -Value 1 -PropertyType DWord -Force | Out-Null"
                ),
                remediation_bat=(
                    ""
                    if ppl_pass
                    else f'reg add "HKLM\\{lsa_key}" /v RunAsPPL /t REG_DWORD /d 1 /f'
                ),
            )
        )

        # 2. Credential Guard (LsaCfgFlags)
        lsa_cfg_flags = self._read_dword("HKLM", lsa_key, "LsaCfgFlags", default_on_non_win=1)
        if lsa_cfg_flags is None:
            lsa_cfg_flags = self._read_dword("HKLM", dg_key, "LsaCfgFlags", default_on_non_win=1)
        cg_pass = lsa_cfg_flags in (1, 2)
        findings.append(
            AuditFinding(
                vector_id="REG-006",
                category=cat_label,
                title="Windows Defender Credential Guard (LsaCfgFlags)" if self.lang == "en" else "Isolasi Virtualisasi Credential Guard (LsaCfgFlags)",
                target=f"HKLM\\{lsa_key}\\LsaCfgFlags",
                status="PASS" if cg_pass else "MEDIUM",
                mitre_id="T1003.001",
                cis_ref="CIS 18.9.5.x (VBS / Credential Guard)",
                current_value=f"LsaCfgFlags={lsa_cfg_flags if lsa_cfg_flags is not None else '0 (Not Configured)'}",
                expected_value="LsaCfgFlags=1 (Enabled with UEFI lock) or 2 (Enabled without lock)",
                description=(
                    f"Credential Guard virtualization-based isolation is configured (LsaCfgFlags={lsa_cfg_flags}), isolating NTLM hashes and Kerberos tickets from the OS kernel."
                    if cg_pass and self.lang == "en"
                    else f"Isolasi berbasis virtualisasi Credential Guard telah dikonfigurasi (LsaCfgFlags={lsa_cfg_flags}), memisahkan hash NTLM dan tiket Kerberos dari memori OS."
                    if cg_pass
                    else "Credential Guard (LsaCfgFlags) is not enabled. Where hardware virtualization (VBS) is supported, enabling Credential Guard isolates LSA secrets."
                    if self.lang == "en"
                    else "Credential Guard (LsaCfgFlags) belum aktif. Jika perangkat keras mendukung Virtualization-Based Security (VBS), aktifkan untuk mengisolasi kredensial LSA."
                ),
                remediation_summary=(
                    "Set LsaCfgFlags=1 (DWORD) under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa on hardware supporting Virtualization-Based Security (VBS)."
                    if self.lang == "en"
                    else "Atur LsaCfgFlags=1 (DWORD) pada HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa pada perangkat keras yang mendukung VBS."
                ),
                remediation_ps1=(
                    ""
                    if cg_pass
                    else f"New-ItemProperty -Path 'HKLM:\\{lsa_key}' -Name 'LsaCfgFlags' -Value 1 -PropertyType DWord -Force | Out-Null"
                ),
                remediation_bat=(
                    ""
                    if cg_pass
                    else f'reg add "HKLM\\{lsa_key}" /v LsaCfgFlags /t REG_DWORD /d 1 /f'
                ),
            )
        )

        # 3. WDigest Cleartext Credential Caching
        wdigest_val = self._read_dword("HKLM", wdigest_key, "UseLogonCredential", default_on_non_win=0)
        wd_pass = wdigest_val in (None, 0)
        findings.append(
            AuditFinding(
                vector_id="REG-007",
                category=cat_label,
                title="WDigest Cleartext Password Caching (UseLogonCredential)" if self.lang == "en" else "Penyimpanan Sandi Teks Terbuka WDigest (UseLogonCredential)",
                target=f"HKLM\\{wdigest_key}\\UseLogonCredential",
                status="PASS" if wd_pass else "CRITICAL",
                mitre_id="T1003.001",
                cis_ref="CIS 18.4.WDigest (L1)",
                current_value=f"UseLogonCredential={wdigest_val if wdigest_val is not None else '0 (Default Disabled)'}",
                expected_value="UseLogonCredential=0 (Disabled)",
                description=(
                    "WDigest cleartext credential caching in LSASS memory is disabled."
                    if wd_pass and self.lang == "en"
                    else "Penyimpanan kredensial teks terbuka (cleartext) WDigest di dalam memori LSASS telah dinonaktifkan."
                    if wd_pass
                    else "UseLogonCredential is set to 1. Windows caches plaintext user passwords inside LSASS process memory, exposing credentials upon memory dump."
                    if self.lang == "en"
                    else "UseLogonCredential bernilai 1. Windows menyimpan kata sandi pengguna dalam bentuk teks terbuka di memori LSASS."
                ),
                remediation_summary=(
                    "Set UseLogonCredential to 0 (DWORD) under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest."
                    if self.lang == "en"
                    else "Atur UseLogonCredential menjadi 0 (DWORD) pada HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest."
                ),
                remediation_ps1=(
                    ""
                    if wd_pass
                    else f"Set-ItemProperty -Path 'HKLM:\\{wdigest_key}' -Name 'UseLogonCredential' -Value 0 -Type DWord -Force"
                ),
                remediation_bat=(
                    ""
                    if wd_pass
                    else f'reg add "HKLM\\{wdigest_key}" /v UseLogonCredential /t REG_DWORD /d 0 /f'
                ),
            )
        )

        return findings
