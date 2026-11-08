import argparse
import json
import sys
from typing import List, Optional

from core import AuditFinding, get_text, __version__, __repo__
from core.service_auditor import ServiceAuditor
from core.registry_auditor import RegistryAuditor
from core.environment_auditor import EnvironmentAuditor
from core.remediation_engine import RemediationEngine
from core.reporter import AuditReporter


def build_arg_parser() -> argparse.ArgumentParser:
    """Configure command-line argument parser for WinHardener."""
    parser = argparse.ArgumentParser(
        prog="winhardener",
        description=(
            "WinHardener: Automated Windows Local Privilege Escalation & Security Posture Auditor. "
            "Performs deterministic host auditing, ACL verification, and CIS/MITRE ATT&CK posture assessment."
        ),
        epilog=f"Repository: {__repo__}",
    )

    audit_group = parser.add_argument_group("Audit Scope Selection")
    audit_group.add_argument(
        "--audit-all",
        action="store_true",
        help="Execute full host security posture assessment across services, registry, ACLs, and environment.",
    )
    audit_group.add_argument(
        "--audit-services",
        action="store_true",
        help="Audit Windows services for Unquoted Service Paths (T1574.009) and binary DACL weaknesses (T1574.010).",
    )
    audit_group.add_argument(
        "--audit-registry",
        action="store_true",
        help="Audit Windows Registry policies: AlwaysInstallElevated (T1548.002), UAC, LSA RunAsPPL (T1003.001), and PowerShell policies.",
    )
    audit_group.add_argument(
        "--audit-acls",
        action="store_true",
        help="Audit filesystem DACLs on service executables (T1574.010) and system PATH directories (T1574.007).",
    )

    output_group = parser.add_argument_group("Remediation & Reporting Options")
    output_group.add_argument(
        "--fix-script",
        choices=["ps1", "bat"],
        default=None,
        help="Generate an administrator-reviewable remediation script in PowerShell ('ps1') or Batch ('bat') format.",
    )
    output_group.add_argument(
        "--fix-output",
        type=str,
        default="",
        help="Custom output file path for the generated remediation script (default: hardening_remediation.ps1/.bat).",
    )
    output_group.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Select primary output format: 'table' for Rich terminal UI (default) or 'json' for structured JSON output.",
    )
    output_group.add_argument(
        "--json-file",
        type=str,
        default="",
        help="Optional file path to save the structured JSON audit report alongside terminal table output.",
    )
    output_group.add_argument(
        "--lang",
        choices=["en", "id"],
        default="en",
        help="Select interface and report language: 'en' (English, default) or 'id' (Bahasa Indonesia).",
    )
    output_group.add_argument(
        "--version",
        action="version",
        version=f"WinHardener v{__version__} ({__repo__})",
    )

    return parser


def execute_audit_workflow(args: argparse.Namespace) -> int:
    """Coordinate selected audit modules, remediation export, and terminal/JSON reporting."""
    lang = args.lang.lower()
    reporter = AuditReporter(lang=lang)
    remediation_engine = RemediationEngine(lang=lang)

    # Default to --audit-all if no individual scope flag was explicitly set
    any_specific = args.audit_services or args.audit_registry or args.audit_acls
    run_all = args.audit_all or not any_specific

    do_services = run_all or args.audit_services
    do_registry = run_all or args.audit_registry
    do_acls = run_all or args.audit_acls

    findings: List[AuditFinding] = []
    host_meta = reporter.get_host_metadata()

    if args.output == "table":
        reporter.render_header_panel(host_meta)
        with reporter.create_progress_bar() as progress:
            total_steps = int(do_services or do_acls) + int(do_registry) + int(do_acls or do_registry) + 1
            task_id = progress.add_task(get_text(lang, "scanning_init"), total=total_steps)

            if do_services or do_acls:
                progress.update(task_id, description=get_text(lang, "scanning_services"))
                svc_auditor = ServiceAuditor(lang=lang)
                findings.extend(
                    svc_auditor.run_all(
                        include_services=do_services,
                        include_acls=do_acls or do_services,
                    )
                )
                progress.advance(task_id)

            if do_registry:
                progress.update(task_id, description=get_text(lang, "scanning_registry"))
                reg_auditor = RegistryAuditor(lang=lang)
                findings.extend(reg_auditor.run_all())
                progress.advance(task_id)

            if do_acls or do_registry:
                progress.update(task_id, description=get_text(lang, "scanning_env"))
                env_auditor = EnvironmentAuditor(lang=lang)
                findings.extend(
                    env_auditor.run_all(
                        include_acls=do_acls,
                        include_registry=do_registry,
                    )
                )
                progress.advance(task_id)

            progress.update(task_id, description=get_text(lang, "scanning_remediation"))
            progress.advance(task_id)
    else:
        if do_services or do_acls:
            svc_auditor = ServiceAuditor(lang=lang)
            findings.extend(
                svc_auditor.run_all(
                    include_services=do_services,
                    include_acls=do_acls or do_services,
                )
            )
        if do_registry:
            reg_auditor = RegistryAuditor(lang=lang)
            findings.extend(reg_auditor.run_all())
        if do_acls or do_registry:
            env_auditor = EnvironmentAuditor(lang=lang)
            findings.extend(
                env_auditor.run_all(
                    include_acls=do_acls,
                    include_registry=do_registry,
                )
            )

    exported_script_path: Optional[str] = None
    if args.fix_script:
        exported_script_path = remediation_engine.export_remediation_script(
            findings=findings,
            script_format=args.fix_script,
            output_path=args.fix_output,
        )

    exported_json_path: Optional[str] = None
    if args.json_file:
        exported_json_path = reporter.export_json_report(findings=findings, output_path=args.json_file)
    elif args.output == "json":
        exported_json_path = reporter.export_json_report(findings=findings, output_path="audit_report.json")

    if args.output == "json":
        payload = reporter.build_json_payload(findings)
        if exported_script_path:
            payload["metadata"]["remediation_script"] = exported_script_path
        if exported_json_path:
            payload["metadata"]["json_report_path"] = exported_json_path
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        reporter.render_master_audit_table(findings)
        reporter.render_executive_summary(
            findings=findings,
            exported_script_path=exported_script_path,
            exported_json_path=exported_json_path,
        )

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for CLI invocation."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return execute_audit_workflow(args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[WinHardener] Audit interrupted by user.\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
