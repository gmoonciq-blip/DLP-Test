"""
Realistic Sensitive Data Scanner
================================

A self-contained Python utility for authorized testing and defensive data
classification. It recursively scans text-based files for possible sensitive
information, assigns confidence and severity, produces JSON/CSV reports, and
optionally writes a redacted copy of scanned text.

The scanner uses only the Python standard library. Pattern matching is an
indicator, not proof that a value is genuine. Human review is recommended.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import math
import os
import re
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Pattern, Sequence, Set, Tuple

APP_NAME = "Realistic Sensitive Data Scanner"
APP_VERSION = "2.2.0"
UTC = timezone.utc
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".log", ".md",
    ".py", ".js", ".ts", ".java", ".cs", ".sql", ".ini", ".cfg", ".conf",
}


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Confidence(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass(frozen=True)
class ScannerConfig:
    root_path: Path
    output_directory: Path
    recursive: bool = True
    redact: bool = False
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    extensions: Set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    excluded_directories: Set[str] = field(
        default_factory=lambda: {".git", ".venv", "venv", "node_modules", "__pycache__"}
    )

    def validate(self) -> None:
        if not self.root_path.exists():
            raise ValueError(f"Input path does not exist: {self.root_path}")
        if self.max_file_size < 1:
            raise ValueError("Maximum file size must be positive")
        if not self.extensions:
            raise ValueError("At least one file extension must be configured")


@dataclass(frozen=True)
class PatternDefinition:
    name: str
    description: str
    expression: Pattern[str]
    severity: Severity
    confidence: Confidence
    validator: Optional[str] = None
    keywords: Tuple[str, ...] = ()


@dataclass
class Finding:
    finding_id: str
    file_path: str
    rule_name: str
    description: str
    severity: Severity
    confidence: Confidence
    line_number: int
    column_start: int
    column_end: int
    masked_value: str
    context: str
    fingerprint: str
    validated: bool

    def to_dict(self) -> Dict[str, object]:
        value = asdict(self)
        value["severity"] = self.severity.value
        value["confidence"] = self.confidence.value
        return value


@dataclass
class FileScanResult:
    file_path: str
    sha256: str
    size_bytes: int
    encoding: str
    duration_ms: float
    findings: List[Finding]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "file_path": self.file_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "encoding": self.encoding,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass
class ScanSummary:
    started_at: str
    completed_at: str
    files_discovered: int
    files_scanned: int
    files_skipped: int
    files_failed: int
    total_bytes: int
    total_findings: int
    findings_by_rule: Dict[str, int]
    findings_by_severity: Dict[str, int]


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True)


def configure_logging(verbose: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(StructuredFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


LOGGER = logging.getLogger("sensitive_data_scanner")


class RuleCatalog:
    """Provides defensive detection rules using realistic syntax."""

    @staticmethod
    def build() -> List[PatternDefinition]:
        return [
            PatternDefinition(
                name="EMAIL_ADDRESS",
                description="Possible email address",
                expression=re.compile(r"(?<![\w.-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
            ),
            PatternDefinition(
                name="IPV4_ADDRESS",
                description="Possible IPv4 address",
                expression=re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                validator="ipv4",
            ),
            PatternDefinition(
                name="PAYMENT_CARD",
                description="Possible payment card number",
                expression=re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                validator="luhn",
                keywords=("card", "visa", "mastercard", "payment", "account"),
            ),
            PatternDefinition(
                name="CANADIAN_SIN",
                description="Possible Canadian Social Insurance Number",
                expression=re.compile(r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}(?!\d)"),
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                validator="luhn",
                keywords=("sin", "social insurance", "employee"),
            ),
            PatternDefinition(
                name="US_SSN",
                description="Possible US Social Security number",
                expression=re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)"),
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                keywords=("ssn", "social security", "taxpayer"),
            ),
            PatternDefinition(
                name="PHONE_NUMBER",
                description="Possible North American phone number",
                expression=re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?[2-9]\d{2}\)?[ .-]?[2-9]\d{2}[ .-]?\d{4}(?!\d)"),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                keywords=("phone", "mobile", "contact", "telephone"),
            ),
            PatternDefinition(
                name="PRIVATE_KEY_HEADER",
                description="Private key material header",
                expression=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
            ),
            PatternDefinition(
                name="CONNECTION_STRING_PASSWORD",
                description="Possible password in a database connection string",
                expression=re.compile(r"(?i)(?:password|pwd)\s*=\s*[^;\s]{6,}"),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                keywords=("server", "database", "connection"),
            ),
            PatternDefinition(
                name="GENERIC_SECRET_ASSIGNMENT",
                description="Possible secret assigned in source code or configuration",
                expression=re.compile(
                    r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b"
                    r"\s*[:=]\s*[\"']?([A-Za-z0-9_./+=:@-]{12,})[\"']?"
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                keywords=("secret", "token", "credential", "authentication"),
            ),
            PatternDefinition(
                name="JWT_LIKE_TOKEN",
                description="Possible JSON Web Token",
                expression=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
            ),
            PatternDefinition(
                name="SENSITIVE_CLASSIFICATION_TERM",
                description="Sensitive classification keyword",
                expression=re.compile(r"(?i)\b(?:strictly confidential|highly confidential|restricted data|trade secret)\b"),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
            ),
        ]


class Validators:
    @staticmethod
    def digits(value: str) -> str:
        return "".join(character for character in value if character.isdigit())

    @classmethod
    def luhn(cls, value: str) -> bool:
        digits = cls.digits(value)
        if not 8 <= len(digits) <= 19 or len(set(digits)) == 1:
            return False
        checksum = 0
        parity = len(digits) % 2
        for index, character in enumerate(digits):
            number = int(character)
            if index % 2 == parity:
                number *= 2
                if number > 9:
                    number -= 9
            checksum += number
        return checksum % 10 == 0

    @staticmethod
    def ipv4(value: str) -> bool:
        try:
            octets = [int(part) for part in value.split(".")]
            return len(octets) == 4 and all(0 <= part <= 255 for part in octets)
        except ValueError:
            return False

    @classmethod
    def execute(cls, validator: Optional[str], value: str) -> bool:
        if validator is None:
            return True
        function = getattr(cls, validator, None)
        if function is None:
            raise ValueError(f"Unknown validator: {validator}")
        return bool(function(value))


class TextDecoder:
    ENCODINGS = ("utf-8-sig", "utf-8", "utf-16", "latin-1")

    def decode(self, raw: bytes) -> Tuple[str, str]:
        for encoding in self.ENCODINGS:
            try:
                return raw.decode(encoding), encoding
            except UnicodeDecodeError:
                continue
        raise UnicodeDecodeError("unknown", raw, 0, 1, "Unable to decode file")


class EntropyAnalyzer:
    """Measures character entropy for generic high-randomness token review."""

    TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9+/=_-]{24,128}\b")

    @staticmethod
    def shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        frequencies = Counter(value)
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in frequencies.values())

    def candidates(self, line: str) -> Iterator[Tuple[re.Match[str], float]]:
        for match in self.TOKEN_PATTERN.finditer(line):
            entropy = self.shannon_entropy(match.group(0))
            if entropy >= 4.2:
                yield match, entropy


class ContextScorer:
    @staticmethod
    def score(line: str, keywords: Sequence[str], pattern_confidence: Confidence) -> Confidence:
        if not keywords:
            return pattern_confidence
        lowered = line.lower()
        hits = sum(1 for keyword in keywords if keyword in lowered)
        if hits >= 2:
            return Confidence.HIGH
        if hits == 1 and pattern_confidence is Confidence.LOW:
            return Confidence.MEDIUM
        if hits == 1 and pattern_confidence is Confidence.MEDIUM:
            return Confidence.HIGH
        return pattern_confidence


class Masker:
    @staticmethod
    def mask(value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        visible = min(4, max(1, len(value) // 6))
        return value[:visible] + ("*" * (len(value) - (visible * 2))) + value[-visible:]

    @staticmethod
    def context(line: str, start: int, end: int, radius: int = 50) -> str:
        left = max(0, start - radius)
        right = min(len(line), end + radius)
        segment = line[left:right].strip()
        relative_start = start - left
        relative_end = end - left
        return segment[:relative_start] + "[REDACTED]" + segment[relative_end:]


class FindingFactory:
    @staticmethod
    def create(
        file_path: Path,
        definition: PatternDefinition,
        match: re.Match[str],
        line: str,
        line_number: int,
        validated: bool,
        confidence: Confidence,
    ) -> Finding:
        raw_value = match.group(0)
        fingerprint_material = (
            f"{file_path}|{definition.name}|{line_number}|{match.start()}|{raw_value}"
        )
        fingerprint = hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest()
        return Finding(
            finding_id=fingerprint[:16],
            file_path=str(file_path),
            rule_name=definition.name,
            description=definition.description,
            severity=definition.severity,
            confidence=confidence,
            line_number=line_number,
            column_start=match.start() + 1,
            column_end=match.end() + 1,
            masked_value=Masker.mask(raw_value),
            context=Masker.context(line, match.start(), match.end()),
            fingerprint=fingerprint,
            validated=validated,
        )


class FileScanner:
    def __init__(self, rules: Sequence[PatternDefinition]):
        self.rules = list(rules)
        self.decoder = TextDecoder()
        self.entropy = EntropyAnalyzer()

    def scan(self, path: Path) -> FileScanResult:
        started = time.perf_counter()
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        text, encoding = self.decoder.decode(raw)
        findings: List[Finding] = []
        seen: Set[str] = set()

        for line_number, line in enumerate(text.splitlines(), start=1):
            for definition in self.rules:
                for match in definition.expression.finditer(line):
                    validated = Validators.execute(definition.validator, match.group(0))
                    if definition.validator and not validated:
                        continue
                    confidence = ContextScorer.score(
                        line, definition.keywords, definition.confidence
                    )
                    finding = FindingFactory.create(
                        path, definition, match, line, line_number, validated, confidence
                    )
                    if finding.fingerprint not in seen:
                        seen.add(finding.fingerprint)
                        findings.append(finding)

            for match, entropy_value in self.entropy.candidates(line):
                if self._overlaps_existing(match, line_number, findings):
                    continue
                definition = PatternDefinition(
                    name="HIGH_ENTROPY_TOKEN",
                    description=f"High-entropy token candidate, entropy={entropy_value:.2f}",
                    expression=self.entropy.TOKEN_PATTERN,
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                )
                finding = FindingFactory.create(
                    path,
                    definition,
                    match,
                    line,
                    line_number,
                    validated=True,
                    confidence=Confidence.LOW,
                )
                if finding.fingerprint not in seen:
                    seen.add(finding.fingerprint)
                    findings.append(finding)

        elapsed = (time.perf_counter() - started) * 1000
        return FileScanResult(
            file_path=str(path),
            sha256=digest,
            size_bytes=len(raw),
            encoding=encoding,
            duration_ms=round(elapsed, 3),
            findings=findings,
        )

    @staticmethod
    def _overlaps_existing(
        match: re.Match[str], line_number: int, findings: Sequence[Finding]
    ) -> bool:
        start = match.start() + 1
        end = match.end() + 1
        return any(
            finding.line_number == line_number
            and not (end <= finding.column_start or start >= finding.column_end)
            for finding in findings
        )


class FileDiscovery:
    def __init__(self, config: ScannerConfig):
        self.config = config

    def discover(self) -> Iterator[Path]:
        root = self.config.root_path
        if root.is_file():
            if self._eligible(root):
                yield root
            return

        iterator = root.rglob("*") if self.config.recursive else root.glob("*")
        for path in iterator:
            if not path.is_file():
                continue
            if any(part in self.config.excluded_directories for part in path.parts):
                continue
            if self._eligible(path):
                yield path

    def _eligible(self, path: Path) -> bool:
        try:
            return (
                path.suffix.lower() in self.config.extensions
                and path.stat().st_size <= self.config.max_file_size
            )
        except OSError:
            return False


class AtomicWriter:
    @staticmethod
    def write_text(target: Path, content: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=target.parent, delete=False
            ) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
                temporary = Path(stream.name)
            temporary.replace(target)
        finally:
            if temporary and temporary.exists():
                temporary.unlink(missing_ok=True)


class RedactionService:
    def redact_file(self, source: Path, findings: Sequence[Finding], destination: Path) -> None:
        text, _ = TextDecoder().decode(source.read_bytes())
        lines = text.splitlines(keepends=True)
        grouped: Dict[int, List[Finding]] = defaultdict(list)
        for finding in findings:
            grouped[finding.line_number].append(finding)

        for line_number, line_findings in grouped.items():
            index = line_number - 1
            if not 0 <= index < len(lines):
                continue
            line = lines[index]
            for finding in sorted(
                line_findings, key=lambda item: item.column_start, reverse=True
            ):
                start = finding.column_start - 1
                end = finding.column_end - 1
                line = line[:start] + "[REDACTED]" + line[end:]
            lines[index] = line
        AtomicWriter.write_text(destination, "".join(lines))


class ReportWriter:
    def __init__(self, output_directory: Path):
        self.output_directory = output_directory

    def write_json(self, results: Sequence[FileScanResult], summary: ScanSummary) -> Path:
        target = self.output_directory / "sensitive_data_scan_report.json"
        payload = {
            "application": APP_NAME,
            "version": APP_VERSION,
            "summary": asdict(summary),
            "files": [result.to_dict() for result in results],
        }
        AtomicWriter.write_text(target, json.dumps(payload, indent=2, sort_keys=True))
        return target

    def write_csv(self, results: Sequence[FileScanResult]) -> Path:
        target = self.output_directory / "sensitive_data_findings.csv"
        target.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "finding_id", "file_path", "rule_name", "description", "severity",
            "confidence", "line_number", "column_start", "column_end",
            "masked_value", "context", "fingerprint", "validated",
        ]
        temporary = target.with_suffix(".csv.tmp")
        with temporary.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for result in results:
                for finding in result.findings:
                    writer.writerow(finding.to_dict())
        temporary.replace(target)
        return target


class ScanCoordinator:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.discovery = FileDiscovery(config)
        self.scanner = FileScanner(RuleCatalog.build())
        self.redactor = RedactionService()
        self.reporter = ReportWriter(config.output_directory)

    def execute(self) -> Tuple[List[FileScanResult], ScanSummary, Path, Path]:
        started = datetime.now(UTC)
        paths = list(self.discovery.discover())
        results: List[FileScanResult] = []
        failed = 0
        total_bytes = 0

        for path in paths:
            try:
                result = self.scanner.scan(path)
                results.append(result)
                total_bytes += result.size_bytes
                LOGGER.info("Scanned %s with %d findings", path, len(result.findings))
                if self.config.redact and result.findings:
                    relative = self._safe_relative(path)
                    destination = self.config.output_directory / "redacted" / relative
                    self.redactor.redact_file(path, result.findings, destination)
            except (OSError, UnicodeError, ValueError) as exc:
                failed += 1
                LOGGER.error("Failed to scan %s: %s", path, exc)
                results.append(
                    FileScanResult(
                        file_path=str(path), sha256="", size_bytes=0,
                        encoding="", duration_ms=0.0, findings=[], error=str(exc)
                    )
                )

        all_findings = [finding for result in results for finding in result.findings]
        by_rule = Counter(finding.rule_name for finding in all_findings)
        by_severity = Counter(finding.severity.value for finding in all_findings)
        completed = datetime.now(UTC)
        summary = ScanSummary(
            started_at=started.isoformat(),
            completed_at=completed.isoformat(),
            files_discovered=len(paths),
            files_scanned=len(paths) - failed,
            files_skipped=0,
            files_failed=failed,
            total_bytes=total_bytes,
            total_findings=len(all_findings),
            findings_by_rule=dict(sorted(by_rule.items())),
            findings_by_severity=dict(sorted(by_severity.items())),
        )
        json_path = self.reporter.write_json(results, summary)
        csv_path = self.reporter.write_csv(results)
        return results, summary, json_path, csv_path

    def _safe_relative(self, path: Path) -> Path:
        if self.config.root_path.is_file():
            return Path(path.name)
        try:
            return path.relative_to(self.config.root_path)
        except ValueError:
            return Path(path.name)


def parse_extensions(value: str) -> Set[str]:
    extensions = set()
    for item in value.split(","):
        cleaned = item.strip().lower()
        if cleaned:
            extensions.add(cleaned if cleaned.startswith(".") else f".{cleaned}")
    return extensions


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--output", default="sensitive_scan_output")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--redact", action="store_true")
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE)
    parser.add_argument(
        "--extensions",
        default=",".join(sorted(DEFAULT_EXTENSIONS)),
        help="Comma-separated file extensions",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def run(argv: Optional[Sequence[str]] = None) -> int:
    arguments = parse_arguments(argv)
    configure_logging(arguments.verbose)
    config = ScannerConfig(
        root_path=Path(arguments.path).expanduser().resolve(),
        output_directory=Path(arguments.output).expanduser().resolve(),
        recursive=not arguments.no_recursive,
        redact=arguments.redact,
        max_file_size=arguments.max_file_size,
        extensions=parse_extensions(arguments.extensions),
    )
    config.validate()
    _, summary, json_path, csv_path = ScanCoordinator(config).execute()
    print(
        json.dumps(
            {
                "summary": asdict(summary),
                "json_report": str(json_path),
                "csv_report": str(csv_path),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if summary.files_failed else 0


def main() -> None:
    try:
        raise SystemExit(run())
    except KeyboardInterrupt:
        LOGGER.warning("Scan interrupted")
        raise SystemExit(130)
    except Exception as exc:
        LOGGER.exception("Scanner failed: %s", exc)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
