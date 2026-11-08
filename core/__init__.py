from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any

__version__ = "1.0.0"
__author__ = "x90d-dev"
__repo__ = "https://github.com/x90d-dev/WinHardener"


@dataclass
class AuditFinding:
    """Represents a single deterministic host configuration or ACL audit result."""
    vector_id: str
    category: str
    title: str
    target: str
    status: str  # "PASS", "INFO", "MEDIUM", "HIGH", "CRITICAL"
    mitre_id: str
    cis_ref: str
    current_value: str
    expected_value: str
    description: str
    remediation_summary: str
    remediation_ps1: str = ""
    remediation_bat: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        "app_title": "WinHardener | Host Configuration & LPE Posture Auditor",
        "app_subtitle": "Deterministic Host Auditing, ACL Verification & Mitigation Strategy",
        "scanning_init": "Initializing host configuration and ACL assessment...",
        "scanning_services": "Auditing Windows Service configurations and binary DACLs...",
        "scanning_registry": "Evaluating Registry elevation controls, UAC, and LSA protection...",
        "scanning_env": "Inspecting system PATH directory ACLs and PowerShell policies...",
        "scanning_remediation": "Synthesizing deterministic remediation strategies...",
        "master_table_title": "Master Host Security Posture Audit Table",
        "col_id": "ID",
        "col_category": "Category",
        "col_vector": "Audit Vector & Target",
        "col_reference": "MITRE / CIS",
        "col_state": "Observed State",
        "col_status": "Posture Status",
        "col_remediation": "Mitigation Strategy",
        "badge_pass": "[SECURE / PASS]",
        "badge_info": "[INFO / AUDIT]",
        "badge_medium": "[MEDIUM RISK]",
        "badge_high": "[HIGH / CRITICAL RISK]",
        "exec_summary_title": "Executive Posture Summary",
        "lbl_host": "Target Hostname",
        "lbl_os": "Operating System",
        "lbl_priv": "Execution Context",
        "lbl_priv_admin": "Elevated (Administrator)",
        "lbl_priv_user": "Standard User (Read-Only Assessment)",
        "lbl_total_vectors": "Total Vectors Tested",
        "lbl_compliance_score": "Posture Compliance Score",
        "lbl_critical_count": "High / Critical Findings",
        "lbl_medium_count": "Medium Risk Findings",
        "lbl_pass_count": "Compliant Controls",
        "lbl_impact": "Estimated Impact",
        "impact_high": "High Risk: Local Privilege Escalation (LPE) or credential exposure paths detected. Prioritize remediation.",
        "impact_medium": "Moderate Risk: Defense-in-depth or policy weaknesses present. Review recommended configuration changes.",
        "impact_low": "Low Risk: Evaluated host controls align with baseline hardening specifications.",
        "script_exported": "Remediation script exported to",
        "json_exported": "Structured JSON audit report saved to",
        "cat_service": "Service Control",
        "cat_registry": "Registry Policy",
        "cat_acl": "Filesystem ACL",
        "cat_powershell": "Script Telemetry",
        "sim_notice": "Non-Windows environment detected: executing deterministic baseline inspection against host environment state.",
    },
    "id": {
        "app_title": "WinHardener | Auditor Postur Keamanan & Eskalasi Hak Akses Host",
        "app_subtitle": "Audit Host Deterministik, Verifikasi ACL & Strategi Mitigasi",
        "scanning_init": "Menginisialisasi asesmen konfigurasi host dan verifikasi ACL...",
        "scanning_services": "Mengaudit konfigurasi layanan Windows dan izin DACL file biner...",
        "scanning_registry": "Mengevaluasi kontrol elevasi Registry, UAC, dan proteksi LSA...",
        "scanning_env": "Memeriksa izin ACL direktori PATH sistem dan kebijakan PowerShell...",
        "scanning_remediation": "Menyusun strategi mitigasi dan remediasi deterministik...",
        "master_table_title": "Tabel Induk Audit Postur Keamanan Host",
        "col_id": "ID",
        "col_category": "Kategori",
        "col_vector": "Vektor Audit & Target",
        "col_reference": "MITRE / CIS",
        "col_state": "Status Teramati",
        "col_status": "Indikator Postur",
        "col_remediation": "Strategi Mitigasi",
        "badge_pass": "[SECURE / PASS]",
        "badge_info": "[INFO / AUDIT]",
        "badge_medium": "[MEDIUM RISK]",
        "badge_high": "[HIGH / CRITICAL RISK]",
        "exec_summary_title": "Ringkasan Eksekutif Postur Keamanan",
        "lbl_host": "Nama Host Target",
        "lbl_os": "Sistem Operasi",
        "lbl_priv": "Konteks Eksekusi",
        "lbl_priv_admin": "Administrator (Hak Akses Penuh)",
        "lbl_priv_user": "Pengguna Standar (Asesmen Baca-Saja)",
        "lbl_total_vectors": "Total Vektor Diuji",
        "lbl_compliance_score": "Skor Kepatuhan Postur",
        "lbl_critical_count": "Jumlah Temuan Kritis / Tinggi",
        "lbl_medium_count": "Jumlah Temuan Risiko Sedang",
        "lbl_pass_count": "Kontrol Sesuai Standar",
        "lbl_impact": "Estimasi Dampak",
        "impact_high": "Risiko Tinggi: Terdeteksi celah eskalasi hak akses lokal (LPE) atau eksposur kredensial. Prioritaskan perbaikan.",
        "impact_medium": "Risiko Sedang: Ditemukan kelemahan kebijakan pertahanan berlapis. Tinjau rekomendasi konfigurasi.",
        "impact_low": "Risiko Rendah: Kontrol host yang diuji telah sesuai dengan spesifikasi baseline penguatan sistem.",
        "script_exported": "Skrip remediasi berhasil diekspor ke",
        "json_exported": "Laporan audit JSON terstruktur disimpan ke",
        "cat_service": "Kontrol Layanan",
        "cat_registry": "Kebijakan Registry",
        "cat_acl": "ACL Sistem File",
        "cat_powershell": "Telemetri Skrip",
        "sim_notice": "Lingkungan non-Windows terdeteksi: menjalankan inspeksi deterministik terhadap variabel lingkungan host.",
    },
}


def get_text(lang: str, key: str) -> str:
    """Retrieve localized UI string for the requested language ('en' or 'id')."""
    selected = TRANSLATIONS.get(lang.lower(), TRANSLATIONS["en"])
    return selected.get(key, TRANSLATIONS["en"].get(key, key))
