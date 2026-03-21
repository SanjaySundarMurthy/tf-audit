"""Core data models for tf-audit."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    SECURITY = "Security"
    NAMING = "Naming Conventions"
    MODULES = "Module Quality"
    BEST_PRACTICES = "Best Practices"
    TAGGING = "Resource Tagging"
    STATE = "State Management"
    PROVIDERS = "Provider Config"


SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

CATEGORY_ICONS = {
    Category.SECURITY: "🔒",
    Category.NAMING: "🏷️",
    Category.MODULES: "📦",
    Category.BEST_PRACTICES: "✅",
    Category.TAGGING: "🏷️",
    Category.STATE: "💾",
    Category.PROVIDERS: "🔌",
}


@dataclass
class Issue:
    """A single audit finding."""
    rule_id: str
    severity: Severity
    category: Category
    message: str
    resource_type: str = ""
    resource_name: str = ""
    file_path: str = ""
    line: Optional[int] = None
    suggestion: Optional[str] = None
    doc_url: Optional[str] = None


@dataclass
class TfResource:
    """A parsed Terraform resource block."""
    resource_type: str
    name: str
    provider: str = ""
    config: dict = field(default_factory=dict)
    file_path: str = ""


@dataclass
class TfFile:
    """Parsed content of a single .tf file."""
    path: str
    resources: list = field(default_factory=list)
    data_sources: list = field(default_factory=list)
    variables: list = field(default_factory=list)
    outputs: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    providers: list = field(default_factory=list)
    terraform_blocks: list = field(default_factory=list)
    locals_blocks: list = field(default_factory=list)
    line_count: int = 0
    raw: dict = field(default_factory=dict)


@dataclass
class AuditReport:
    """Full audit report."""
    scan_path: str
    total_files: int = 0
    total_resources: int = 0
    tf_files: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    providers_found: list = field(default_factory=list)
    score: float = 100.0
    grade: str = "A+"

    @property
    def critical_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.LOW)

    @property
    def info_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.INFO)

    def calculate_score(self):
        """Calculate audit score based on issue severities."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 6,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        total_deductions = sum(weights[i.severity] for i in self.issues)
        max_deduction = max(self.total_resources * 20, 80)
        self.score = max(0, round(100 - (total_deductions / max(max_deduction, 1)) * 100, 1))

        if self.score >= 95:
            self.grade = "A+"
        elif self.score >= 90:
            self.grade = "A"
        elif self.score >= 85:
            self.grade = "A-"
        elif self.score >= 80:
            self.grade = "B+"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 70:
            self.grade = "B-"
        elif self.score >= 65:
            self.grade = "C+"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 55:
            self.grade = "C-"
        elif self.score >= 50:
            self.grade = "D"
        elif self.score >= 40:
            self.grade = "D-"
        else:
            self.grade = "F"
