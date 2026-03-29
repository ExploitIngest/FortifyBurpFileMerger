"""
merge_findings.py
-----------------
Combine and de-duplicate security findings from Burp Suite and Fortify XML exports.

Usage:
    python merge_findings.py [OPTIONS]

Options:
    --burp PATH         Path to Burp Suite XML file  (default: burp_findings.xml)
    --fortify PATH      Path to Fortify XML file     (default: fortify_findings.xml)
    --output PATH       Output XML file path         (default: merged_findings.xml)
    --severity LEVEL    Minimum severity to include  (default: all)
                        Choices: critical, high, medium, low, info
    --verbose           Print summary table to stdout
"""

import argparse
import hashlib
import logging
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(levelname)s: %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering (higher index = higher severity)
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """Normalised security finding, source-agnostic."""
    source: str                          # "burp" | "fortify"
    issue_type: str                      # vulnerability class / category
    severity: str                        # normalised to lowercase
    host: str                            # target host / file path
    location: str                        # URL path, class, or file location
    detail: str                          # description / abstract
    recommendation: str = ""             # remediation text
    raw_xml: Optional[str] = field(default=None, repr=False)

    # ------------------------------------------------------------------
    # De-duplication key: same type + host + location = duplicate
    # ------------------------------------------------------------------
    @property
    def fingerprint(self) -> str:
        key = f"{self.issue_type.lower()}|{self.host.lower()}|{self.location.lower()}"
        return hashlib.sha256(key.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------
    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.index(self.severity) if self.severity in SEVERITY_ORDER else -1

    def meets_minimum(self, minimum: Optional[str]) -> bool:
        if not minimum:
            return True
        min_rank = SEVERITY_ORDER.index(minimum.lower()) if minimum in SEVERITY_ORDER else -1
        return self.severity_rank >= min_rank


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _text(element: Optional[ET.Element], default: str = "") -> str:
    """Safely extract and strip text from an XML element."""
    if element is None:
        return default
    return (element.text or "").strip()


def parse_burp(path: Path) -> list[Finding]:
    """
    Parse a Burp Suite Pro XML export.

    Burp's exported XML structure (simplified):
        <issues burpVersion="..." exportTime="...">
          <issue>
            <serialNumber/>
            <type/>
            <name/>              <- issue_type
            <host ip="...">...</host>
            <path/>              <- location
            <severity/>
            <confidence/>
            <issueBackground/>
            <remediationBackground/>
            <issueDetail/>       <- detail
            <remediationDetail/>
          </issue>
        </issues>
    """
    findings: list[Finding] = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        log.error("Failed to parse Burp file '%s': %s", path, exc)
        return findings

    # Burp top-level tag may be <issues> or <BurpSuite>
    issue_iter = root.iter("issue") if root.tag != "issue" else [root]

    for item in issue_iter:
        severity_raw = _text(item.find("severity"))
        findings.append(Finding(
            source="burp",
            issue_type=_text(item.find("name"), "Unknown"),
            severity=_normalise_severity_burp(severity_raw),
            host=_text(item.find("host"), "unknown"),
            location=_text(item.find("path"), "/"),
            detail=(
                _text(item.find("issueDetail"))
                or _text(item.find("issueBackground"))
            ),
            recommendation=(
                _text(item.find("remediationDetail"))
                or _text(item.find("remediationBackground"))
            ),
            raw_xml=ET.tostring(item, encoding="unicode"),
        ))

    log.info("  Burp   : parsed %d finding(s) from '%s'", len(findings), path)
    return findings


def _normalise_severity_burp(raw: str) -> str:
    mapping = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "information": "info",
        "info": "info",
    }
    return mapping.get(raw.lower(), "info")


def parse_fortify(path: Path) -> list[Finding]:
    """
    Parse a Fortify Software Security Center (SSC) XML / FPR audit XML export.

    Common Fortify XML structure:
        <FVDL ...>
          <Vulnerabilities>
            <Vulnerability>
              <ClassInfo>
                <Type/>            <- issue_type
                <Severity/>
              </ClassInfo>
              <InstanceInfo>
                <InstanceSeverity/>
              </InstanceInfo>
              <AnalysisInfo>
                <Unified>
                  <Trace>
                    <Primary>
                      <Entry><Node><SourceLocation path="..." line="..."/></Node></Entry>
                    </Primary>
                  </Trace>
                </Unified>
              </AnalysisInfo>
            </Vulnerability>
          </Vulnerabilities>
          <Description defClassID="...">
            <Abstract/>
            <Explanation/>
            <Recommendations/>
          </Description>
        </FVDL>

    Also handles simpler flat exports:
        <ReportSection><Title/><Issues><Issue>...</Issue></Issues></ReportSection>
    """
    findings: list[Finding] = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        log.error("Failed to parse Fortify file '%s': %s", path, exc)
        return findings

    # --- FVDL format ---
    ns_match = root.tag.startswith("{")
    ns = root.tag.split("}")[0].lstrip("{") if ns_match else ""
    ns_prefix = f"{{{ns}}}" if ns else ""

    vulnerabilities = root.findall(f".//{ns_prefix}Vulnerability")
    if vulnerabilities:
        for vuln in vulnerabilities:
            class_info = vuln.find(f"{ns_prefix}ClassInfo")
            instance_info = vuln.find(f"{ns_prefix}InstanceInfo")

            issue_type = _text(
                class_info.find(f"{ns_prefix}Type") if class_info is not None else None,
                "Unknown",
            )
            severity_raw = (
                _text(instance_info.find(f"{ns_prefix}InstanceSeverity") if instance_info else None)
                or _text(class_info.find(f"{ns_prefix}Severity") if class_info else None)
            )

            # Source location
            src_loc = vuln.find(f".//{ns_prefix}SourceLocation")
            file_path = src_loc.get("path", "unknown") if src_loc is not None else "unknown"
            line = src_loc.get("line", "") if src_loc is not None else ""
            location = f"{file_path}:{line}" if line else file_path

            findings.append(Finding(
                source="fortify",
                issue_type=issue_type,
                severity=_normalise_severity_fortify(severity_raw),
                host=file_path,
                location=location,
                detail="",        # Descriptions live in a separate <Description> block
                raw_xml=ET.tostring(vuln, encoding="unicode"),
            ))
    else:
        # --- Flat <Issue> export (Fortify report HTML/XML) ---
        for item in root.iter("Issue"):
            sev = _text(item.find("Severity") or item.find("severity"))
            findings.append(Finding(
                source="fortify",
                issue_type=_text(item.find("Category") or item.find("Type"), "Unknown"),
                severity=_normalise_severity_fortify(sev),
                host=_text(item.find("FilePath") or item.find("file"), "unknown"),
                location=_text(item.find("FilePath") or item.find("path"), "unknown"),
                detail=_text(item.find("Abstract") or item.find("detail")),
                recommendation=_text(item.find("Recommendation") or item.find("recommendation")),
                raw_xml=ET.tostring(item, encoding="unicode"),
            ))

    log.info("  Fortify: parsed %d finding(s) from '%s'", len(findings), path)
    return findings


def _normalise_severity_fortify(raw: str) -> str:
    try:
        val = float(raw)
        if val >= 4.0:
            return "critical"
        if val >= 3.0:
            return "high"
        if val >= 2.0:
            return "medium"
        if val >= 1.0:
            return "low"
        return "info"
    except ValueError:
        pass
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "information": "info",
    }
    return mapping.get(raw.lower(), "info")


# ---------------------------------------------------------------------------
# De-duplication
# ---------------------------------------------------------------------------

def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicates by fingerprint.
    When duplicates exist across sources, the Burp finding is preferred
    (it typically carries richer HTTP context).  Within the same source,
    the first occurrence wins.
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint
        if fp not in seen:
            seen[fp] = f
        elif seen[fp].source != "burp" and f.source == "burp":
            # Prefer Burp over Fortify for duplicates
            seen[fp] = f
    return list(seen.values())


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def build_output_xml(findings: list[Finding]) -> ET.ElementTree:
    """Produce a unified, source-agnostic XML document."""
    root = ET.Element("Findings", count=str(len(findings)))

    for f in sorted(findings, key=lambda x: -x.severity_rank):
        el = ET.SubElement(root, "Finding",
                           source=f.source,
                           severity=f.severity)
        ET.SubElement(el, "IssueType").text = f.issue_type
        ET.SubElement(el, "Host").text = f.host
        ET.SubElement(el, "Location").text = f.location
        ET.SubElement(el, "Detail").text = f.detail
        ET.SubElement(el, "Recommendation").text = f.recommendation

    ET.indent(root, space="  ")
    return ET.ElementTree(root)


def print_summary(findings: list[Finding]) -> None:
    """Print a severity-breakdown table to stdout."""
    counts: dict[str, dict[str, int]] = {
        sev: {"burp": 0, "fortify": 0} for sev in reversed(SEVERITY_ORDER)
    }
    for f in findings:
        counts[f.severity][f.source] += 1

    print("\n╔══════════════════════════════════════════╗")
    print("║          Merged Findings Summary          ║")
    print("╠═══════════╦══════════╦═══════════╦════════╣")
    print("║ Severity  ║   Burp   ║  Fortify  ║ Total  ║")
    print("╠═══════════╬══════════╬═══════════╬════════╣")
    grand_total = 0
    for sev in reversed(SEVERITY_ORDER):
        b = counts[sev]["burp"]
        fo = counts[sev]["fortify"]
        t = b + fo
        grand_total += t
        print(f"║ {sev:<9} ║ {b:^8} ║ {fo:^9} ║ {t:^6} ║")
    print("╠═══════════╩══════════╩═══════════╬════════╣")
    print(f"║ Total                             ║ {grand_total:^6} ║")
    print("╚═══════════════════════════════════╩════════╝\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge and de-duplicate Burp Suite + Fortify XML findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--burp",     default="burp_findings.xml",    metavar="PATH")
    parser.add_argument("--fortify",  default="fortify_findings.xml", metavar="PATH")
    parser.add_argument("--output",   default="merged_findings.xml",  metavar="PATH")
    parser.add_argument("--severity", default=None, choices=SEVERITY_ORDER, metavar="LEVEL",
                        help="Minimum severity to include (default: all)")
    parser.add_argument("--verbose",  action="store_true",
                        help="Print summary table to stdout")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    burp_path    = Path(args.burp)
    fortify_path = Path(args.fortify)
    output_path  = Path(args.output)

    # --- Validate inputs ---
    missing = [p for p in (burp_path, fortify_path) if not p.exists()]
    if missing:
        for p in missing:
            log.error("Input file not found: '%s'", p)
        return 1

    # --- Parse ---
    log.info("Parsing input files …")
    all_findings: list[Finding] = []
    all_findings.extend(parse_burp(burp_path))
    all_findings.extend(parse_fortify(fortify_path))
    log.info("  Total  : %d finding(s) before de-duplication", len(all_findings))

    # --- Filter by severity ---
    if args.severity:
        all_findings = [f for f in all_findings if f.meets_minimum(args.severity)]
        log.info("  Filtered to severity >= '%s': %d finding(s)", args.severity, len(all_findings))

    # --- De-duplicate ---
    unique = deduplicate(all_findings)
    removed = len(all_findings) - len(unique)
    log.info("  De-duplicated: removed %d duplicate(s), %d unique finding(s) remain", removed, len(unique))

    # --- Write output ---
    tree = build_output_xml(unique)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    log.info("Merged findings written to '%s'", output_path)

    # --- Optional summary ---
    if args.verbose:
        print_summary(unique)

    return 0


if __name__ == "__main__":
    sys.exit(main())
