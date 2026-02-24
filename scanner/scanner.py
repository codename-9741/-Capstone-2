import sys
import ssl
import socket
import time
import json
import re
import math
import threading
import datetime
import os
import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin

import requests

from PyQt6.QtCore import (
    Qt, QObject, QThread, QTimer, QSize, pyqtSignal, QUrl
)
from PyQt6.QtGui import (
    QColor, QPainter, QPen, QBrush, QFont, QLinearGradient
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QGridLayout, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox, QProgressBar,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QMessageBox, QFrame, QSizePolicy, QFormLayout
)

# Optional: Embedded web view
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView  # type: ignore
    HAS_WEBENGINE = True
except Exception:
    HAS_WEBENGINE = False

# Optional: better link extraction
try:
    from bs4 import BeautifulSoup  # type: ignore
    HAS_BS4 = True
except Exception:
    HAS_BS4 = False

# PDF export
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    HAS_REPORTLAB = True
except Exception:
    HAS_REPORTLAB = False


# ──────────────────────────────────────────────────────────────────────────────
# THEME (Neo-Violet Corporate)
# ──────────────────────────────────────────────────────────────────────────────
THEME = """
QMainWindow, QWidget {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #070212, stop:0.45 #0b0520, stop:1 #070212);
    color: #EAF2FF;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 11px;
}

QTabWidget::pane {
    border: 1px solid rgba(168, 85, 247, 0.35);
    border-radius: 14px;
    background: rgba(0,0,0,0.22);
}

QTabBar::tab {
    background: rgba(0,0,0,0.28);
    border: 1px solid rgba(168, 85, 247, 0.35);
    padding: 10px 16px;
    margin-right: 6px;
    color: #cbb6ff;
    font-weight: 700;
    letter-spacing: 0.8px;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
}

QTabBar::tab:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(168, 85, 247, 0.55), stop:1 rgba(0, 229, 255, 0.18));
    color: #FFFFFF;
    border: 1px solid rgba(0, 229, 255, 0.65);
}

QGroupBox {
    border: 1px solid rgba(168, 85, 247, 0.32);
    border-radius: 12px;
    margin-top: 18px;
    padding: 12px;
    background: rgba(0,0,0,0.24);
    font-weight: 800;
    color: #00E5FF;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 8px;
    color: #00E5FF;
    font-size: 11px;
    letter-spacing: 1.2px;
}

QLineEdit, QPlainTextEdit, QComboBox {
    background: rgba(0,0,0,0.48);
    border: 1px solid rgba(168, 85, 247, 0.32);
    border-radius: 10px;
    color: #EAF2FF;
    padding: 8px;
}

QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid rgba(0, 229, 255, 0.85);
    background: rgba(0, 229, 255, 0.08);
}

QTableWidget {
    background: rgba(0,0,0,0.45);
    border: 1px solid rgba(168, 85, 247, 0.28);
    border-radius: 12px;
    gridline-color: rgba(168, 85, 247, 0.12);
    alternate-background-color: rgba(168, 85, 247, 0.06);
}

QHeaderView::section {
    background: rgba(0,0,0,0.55);
    color: #00E5FF;
    border: 1px solid rgba(168, 85, 247, 0.22);
    padding: 8px;
    font-weight: 900;
    letter-spacing: 0.8px;
}

QTableWidget::item:selected {
    background: rgba(168, 85, 247, 0.35);
    color: #FFFFFF;
}

QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(168, 85, 247, 0.92),
        stop:0.5 rgba(0, 229, 255, 0.50),
        stop:1 rgba(236, 72, 153, 0.42));
    border: 1px solid rgba(0, 229, 255, 0.55);
    border-radius: 12px;
    color: #FFFFFF;
    padding: 10px 14px;
    font-weight: 900;
    letter-spacing: 1.2px;
    text-transform: uppercase;
}

QPushButton:hover {
    border: 1px solid rgba(255, 255, 255, 0.6);
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(200, 120, 255, 0.98),
        stop:1 rgba(0, 255, 255, 0.62));
}

QPushButton:disabled {
    background: rgba(60,60,80,0.25);
    color: rgba(220,220,255,0.28);
    border: 1px solid rgba(120,120,170,0.18);
}

QProgressBar {
    border: 1px solid rgba(168, 85, 247, 0.30);
    border-radius: 10px;
    text-align: center;
    color: #FFFFFF;
    background: rgba(0,0,0,0.45);
    font-weight: 900;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #00E5FF, stop:0.5 #A855F7, stop:1 #EC4899);
    border-radius: 8px;
}
"""


# ──────────────────────────────────────────────────────────────────────────────
# MODELS
# ──────────────────────────────────────────────────────────────────────────────
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_COLOR = {
    "Critical": QColor("#F87171"),
    "High": QColor("#FB923C"),
    "Medium": QColor("#FACC15"),
    "Low": QColor("#4ADE80"),
    "Info": QColor("#93C5FD"),
}
CONF_MULT = {"High": 1.0, "Medium": 0.8, "Low": 0.6}


@dataclass
class Finding:
    severity: str
    category: str
    confidence: str
    finding: str
    remediation: str
    evidence: str = ""
    http_method: str = ""
    outcome: str = ""


@dataclass
class HttpMatrixItem:
    method: str
    allowed: str
    status: str
    notes: str = ""


@dataclass
class BrokenLinkItem:
    url: str
    status: str
    note: str = ""


@dataclass
class NetworkDiag:
    dns_ips: List[str] = field(default_factory=list)
    ipv6_present: bool = False

    rtt_80_ms: Optional[int] = None
    rtt_443_ms: Optional[int] = None

    http_redirect_to_https: Optional[bool] = None

    tls_version: str = ""
    tls_cipher: str = ""
    tls_alpn: str = ""

    cert_subject: str = ""
    cert_issuer: str = ""
    cert_days_left: Optional[int] = None


@dataclass
class AuthConfig:
    enabled: bool = False
    auth_type: str = "None"  # None, Basic, Bearer, Header
    username: str = ""
    password: str = ""
    token: str = ""
    header_name: str = ""
    header_value: str = ""


@dataclass
class ScanConfig:
    # existing modules
    mod_headers: bool = True
    mod_tls: bool = True
    mod_cookies: bool = True
    mod_cors: bool = True
    mod_clickjacking: bool = True
    mod_exposures: bool = True
    mod_robots_securitytxt: bool = True
    mod_broken_links: bool = True
    mod_network: bool = True
    mod_http_matrix: bool = True

    # NEW modules (requested capabilities)
    mod_ai_reco: bool = True
    mod_cve_intel: bool = True
    mod_js_secrets: bool = True
    mod_subdomains: bool = True            # passive CT only
    mod_waf_detect: bool = True            # detection + hardening, no bypass
    mod_cloud_storage: bool = True         # passive refs + HEAD check
    mod_graphql: bool = True               # safe probe
    mod_websocket: bool = True             # passive refs
    mod_rate_limit: bool = False           # gated by Authorized Mode
    mod_history: bool = True               # local history file
    mod_compliance: bool = True            # OWASP/PCI/ISO mapping
    mod_adv_network: bool = True           # enhanced diagnostics (NOT port scanning)

    # behavior
    follow_redirects: bool = True
    verify_ssl: bool = True
    timeout: int = 15
    rate_delay: float = 0.15

    # HTTP profile (Scanner tab)
    http_profile: str = "Safe"  # Safe/Extended/Aggressive (Aggressive needs authorized_mode)
    authorized_mode: bool = False
    allow_dangerous_methods: bool = False  # TRACE probe (off by default)

    # Limits / safety knobs
    js_max_files: int = 12
    js_max_bytes: int = 220_000
    cve_max_queries: int = 4
    rate_limit_burst: int = 12

    # history storage
    history_path: str = ""  # empty => auto in user profile

    # UI behavior
    open_external_browser: bool = False


@dataclass
class ScanResult:
    target: str
    started_at: str
    duration_s: float
    risk_score: int
    risk_grade: str
    requests_ok: int
    requests_total: int

    findings: List[Finding] = field(default_factory=list)
    http_matrix: List[HttpMatrixItem] = field(default_factory=list)
    broken_links: List[BrokenLinkItem] = field(default_factory=list)
    network: NetworkDiag = field(default_factory=NetworkDiag)

    # NEW outputs
    discovery: Dict[str, Any] = field(default_factory=dict)
    cve_intel: List[Dict[str, Any]] = field(default_factory=list)
    compliance: Dict[str, List[str]] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    history: Dict[str, Any] = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return "https://"
    if "://" not in u:
        return "https://" + u
    return u


def risk_band(score: int) -> Tuple[str, QColor]:
    if score <= 29:
        return "LOW", QColor("#4ADE80")
    if score <= 69:
        return "MEDIUM", QColor("#F59E0B")
    return "HIGH", QColor("#F87171")


def safe_token_wrap(s: str, chunk: int = 34) -> str:
    if not s:
        return s
    parts = []
    for tok in re.split(r"(\s+)", s):
        if len(tok) > chunk and not tok.isspace():
            tok = " ".join(tok[i:i + chunk] for i in range(0, len(tok), chunk))
        parts.append(tok)
    return "".join(parts)


def sanitize_pdf_text(s: str) -> str:
    if not s:
        return ""
    rep = {
        "—": "-",
        "–": "-",
        "→": "->",
        "•": "*",
        "✅": "[OK]",
        "⚠️": "[WARN]",
        "❌": "[X]",
    }
    out = s
    for k, v in rep.items():
        out = out.replace(k, v)
    out = "".join(ch for ch in out if ord(ch) < 0x1F000)
    return safe_token_wrap(out)


def now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def mask_secret(s: str, keep: int = 4) -> str:
    if not s:
        return s
    s = s.strip()
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + ("*" * (len(s) - keep * 2)) + s[-keep:]


def is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except Exception:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except Exception:
            return False


def base_domain(host: str) -> str:
    h = (host or "").split(":")[0].strip().lower()
    if not h or is_ip(h):
        return h
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    two_level = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if len(parts[-1]) == 2 and parts[-2] in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_script_srcs(html: str) -> List[str]:
    if not html:
        return []
    out = []
    for m in re.finditer(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, re.I):
        out.append(m.group(1).strip())
    return out


def find_ws_refs(text: str) -> List[str]:
    if not text:
        return []
    refs = re.findall(r"\bws{1,2}://[^\s\"'<>]+", text, flags=re.I)
    return list(dict.fromkeys(refs))[:50]


def find_cloud_refs(text: str) -> Dict[str, List[str]]:
    s = text or ""
    s3 = re.findall(r"\bhttps?://[a-z0-9.\-]{3,63}\.s3[.-][a-z0-9-]+\.amazonaws\.com/[^\s\"'<>]+", s, re.I)
    s3_alt = re.findall(r"\bhttps?://s3\.amazonaws\.com/[a-z0-9.\-]{3,63}/[^\s\"'<>]+", s, re.I)
    azure = re.findall(r"\bhttps?://[a-z0-9-]{3,63}\.blob\.core\.windows\.net/[^\s\"'<>]+", s, re.I)
    gcp = re.findall(r"\bhttps?://storage\.googleapis\.com/[^\s\"'<>]+", s, re.I) + \
          re.findall(r"\bhttps?://[a-z0-9.\-]{3,63}\.storage\.googleapis\.com/[^\s\"'<>]+", s, re.I)

    def dedup(x): return list(dict.fromkeys(x))[:50]

    return {
        "aws_s3": dedup(s3 + s3_alt),
        "azure_blob": dedup(azure),
        "gcp_storage": dedup(gcp),
    }


# ──────────────────────────────────────────────────────────────────────────────
# VISUAL WIDGETS (Gauge + Globe telemetry)
# ──────────────────────────────────────────────────────────────────────────────
class RiskGauge(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self._band = "LOW"
        self._color = QColor("#4ADE80")
        self.setMinimumHeight(110)
        self.setMinimumWidth(220)

        self._anim_t = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)

    def set_score(self, score: int):
        self._score = max(0, min(100, int(score)))
        self._band, self._color = risk_band(self._score)
        self.update()

    def _tick(self):
        self._anim_t += 0.06
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w, h = self.width(), self.height()
        cx, cy = w * 0.52, h * 0.80
        r = min(w, h) * 0.55

        base_pen = QPen(QColor(255, 255, 255, 40), 10)
        base_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(base_pen)
        p.drawArc(int(cx - r), int(cy - r), int(2 * r), int(2 * r), 180 * 16, 180 * 16)

        span = int(180 * (self._score / 100.0) * 16)

        glow_alpha = 120 + int(60 * (0.5 + 0.5 * math.sin(self._anim_t)))
        active = QColor(self._color)
        active.setAlpha(glow_alpha)

        active_pen = QPen(active, 10)
        active_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(active_pen)
        p.drawArc(int(cx - r), int(cy - r), int(2 * r), int(2 * r), 180 * 16, span)

        p.setPen(QColor("#EAF2FF"))
        p.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        p.drawText(10, 18, "RISK")

        p.setFont(QFont("Segoe UI", 14, QFont.Weight.Black))
        p.drawText(10, 46, f"{self._score}/100")

        p.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        p.setPen(self._color)
        p.drawText(10, 70, self._band)

        p.end()


class GlobeTelemetry(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._t = 0.0
        self._active = False
        self.setMinimumHeight(160)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)

    def set_active(self, active: bool):
        self._active = active

    def _tick(self):
        self._t += 0.05 if self._active else 0.015
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w, h = self.width(), self.height()
        cx, cy = w * 0.5, h * 0.5
        r = min(w, h) * 0.38

        bg = QLinearGradient(0, 0, w, h)
        bg.setColorAt(0.0, QColor(0, 0, 0, 0))
        bg.setColorAt(1.0, QColor(168, 85, 247, 30))
        p.fillRect(0, 0, w, h, bg)

        outline = QPen(QColor(0, 229, 255, 120), 2)
        p.setPen(outline)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(int(cx - r), int(cy - r), int(2 * r), int(2 * r))

        grid_pen = QPen(QColor(168, 85, 247, 90), 1)
        p.setPen(grid_pen)
        for i in range(-2, 3):
            yy = cy + (i * r * 0.35)
            rx = r * math.cos((i * 0.22))
            p.drawEllipse(int(cx - rx), int(yy - r * 0.12), int(2 * rx), int(2 * r * 0.12))

        for k in range(6):
            ang = self._t + k * (math.pi / 6.0)
            rx = r * abs(math.cos(ang))
            p.drawEllipse(int(cx - rx), int(cy - r), int(2 * rx), int(2 * r))

        dot_pen = QPen(QColor(0, 229, 255, 180), 1)
        p.setPen(dot_pen)
        p.setBrush(QBrush(QColor(0, 229, 255, 160)))

        for k in range(18):
            a = self._t * (1.2 if self._active else 0.6) + k * 0.4
            x = cx + math.cos(a) * r * 0.85
            y = cy + math.sin(a * 1.3) * r * 0.55
            p.drawEllipse(int(x - 2), int(y - 2), 4, 4)

        p.setPen(QColor("#EAF2FF"))
        p.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        p.drawText(10, 18, "LIVE TELEMETRY")
        p.setPen(QColor(200, 200, 255, 140))
        p.setFont(QFont("Segoe UI", 8))
        p.drawText(10, 36, "visual heartbeat (simulated)")

        p.end()


def card_frame() -> QFrame:
    fr = QFrame()
    fr.setFrameShape(QFrame.Shape.NoFrame)
    fr.setStyleSheet("""
        QFrame {
            background: rgba(0,0,0,0.25);
            border: 1px solid rgba(168, 85, 247, 0.28);
            border-radius: 14px;
        }
    """)
    return fr


class HudCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame {
                background: rgba(0,0,0,0.24);
                border: 1px solid rgba(168, 85, 247, 0.28);
                border-radius: 14px;
            }
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(4)
        self.title = QLabel(title)
        self.title.setStyleSheet("color: rgba(0,229,255,0.90); font-weight: 900; letter-spacing: 1.2px;")
        self.value = QLabel("—")
        self.value.setStyleSheet("font-size: 18px; font-weight: 900;")
        self.sub = QLabel("")
        self.sub.setStyleSheet("color: rgba(234,242,255,0.70);")
        lay.addWidget(self.title)
        lay.addWidget(self.value)
        lay.addWidget(self.sub)

    def set_value(self, text: str, sub: str = "", color: Optional[QColor] = None):
        self.value.setText(text)
        self.sub.setText(sub)
        if color:
            self.value.setStyleSheet(f"font-size: 18px; font-weight: 900; color: {color.name()};")
        else:
            self.value.setStyleSheet("font-size: 18px; font-weight: 900;")


# ──────────────────────────────────────────────────────────────────────────────
# SCANNER ENGINE (defensive checks)
# ──────────────────────────────────────────────────────────────────────────────
class NightfallScanner:
    def __init__(
        self,
        target: str,
        cfg: ScanConfig,
        auth: AuthConfig,
        cancel_evt: threading.Event,
        log_fn=None,
        progress_fn=None,
    ):
        self.target = normalize_url(target)
        self.cfg = cfg
        self.auth = auth
        self.cancel_evt = cancel_evt
        self.log = log_fn or (lambda s: None)
        self.progress = progress_fn or (lambda pct, msg: None)

        self.parsed = urlparse(self.target)
        self.origin = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.host = self.parsed.netloc

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "NIGHTFALL-TSUKUYOMI (Defensive Audit; Authorized Use Only)"
        })

        self._apply_auth()

        self.req_total = 0
        self.req_ok = 0

        self.findings: List[Finding] = []
        self.http_matrix: List[HttpMatrixItem] = []
        self.broken_links: List[BrokenLinkItem] = []
        self.network = NetworkDiag()

        # NEW outputs
        self.discovery: Dict[str, Any] = {}
        self.cve_intel: List[Dict[str, Any]] = []
        self.compliance: Dict[str, List[str]] = {}
        self.recommendations: List[str] = []
        self.history: Dict[str, Any] = {}

    def _apply_auth(self):
        if not self.auth.enabled or self.auth.auth_type == "None":
            return
        if self.auth.auth_type == "Basic":
            self.session.auth = (self.auth.username, self.auth.password)
        elif self.auth.auth_type == "Bearer":
            self.session.headers["Authorization"] = f"Bearer {self.auth.token}"
        elif self.auth.auth_type == "Header":
            if self.auth.header_name.strip():
                self.session.headers[self.auth.header_name.strip()] = self.auth.header_value.strip()

    def _sleep(self):
        if self.cfg.rate_delay > 0:
            time.sleep(self.cfg.rate_delay)

    def _req(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Wrapper for requests with override support:
        - allow_redirects, verify, timeout can be overridden per call.
        """
        if self.cancel_evt.is_set():
            return None

        self.req_total += 1
        try:
            allow_redirects = kwargs.pop("allow_redirects", self.cfg.follow_redirects)
            verify = kwargs.pop("verify", self.cfg.verify_ssl)
            timeout = kwargs.pop("timeout", self.cfg.timeout)

            r = self.session.request(
                method=method,
                url=url,
                timeout=timeout,
                verify=verify,
                allow_redirects=allow_redirects,
                **kwargs
            )
            self.req_ok += 1
            return r
        except Exception as e:
            self.log(f"[net] {method} {url} failed: {type(e).__name__}")
            return None

    def add_finding(
        self,
        severity: str,
        category: str,
        confidence: str,
        finding: str,
        remediation: str,
        evidence: str = "",
        http_method: str = "",
        outcome: str = "",
    ):
        self.findings.append(Finding(
            severity=severity,
            category=category,
            confidence=confidence,
            finding=finding,
            remediation=remediation,
            evidence=evidence,
            http_method=http_method,
            outcome=outcome
        ))

    # ───────────── checks ─────────────
    def check_headers(self, headers: Dict[str, str]):
        want = {
            "Content-Security-Policy": ("High", "Implement CSP (start: default-src 'self')."),
            "Strict-Transport-Security": ("Medium", "Enable HSTS (max-age=31536000; includeSubDomains)."),
            "X-Content-Type-Options": ("Low", "Set X-Content-Type-Options: nosniff."),
            "Referrer-Policy": ("Low", "Set Referrer-Policy: strict-origin-when-cross-origin."),
            "Permissions-Policy": ("Low", "Define Permissions-Policy (least privilege)."),
        }
        for h, (sev, rem) in want.items():
            if h not in headers:
                self.add_finding(
                    severity=sev,
                    category="Headers",
                    confidence="High",
                    finding=f"Missing security header: {h}",
                    remediation=rem,
                    evidence="Header absent",
                    http_method="GET",
                    outcome="Missing"
                )

    def check_clickjacking(self, headers: Dict[str, str]):
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")
        has_frame_anc = "frame-ancestors" in csp.lower()
        if not xfo and not has_frame_anc:
            self.add_finding(
                severity="Medium",
                category="Clickjacking",
                confidence="Medium",
                finding="Clickjacking protection not detected (no X-Frame-Options and no CSP frame-ancestors).",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                evidence="XFO missing; CSP frame-ancestors missing",
                http_method="GET",
                outcome="Not protected"
            )

    def check_cookies(self, response: requests.Response):
        set_cookies: List[str] = []
        try:
            set_cookies = response.raw.headers.getlist("Set-Cookie")  # type: ignore
        except Exception:
            sc = response.headers.get("Set-Cookie", "")
            if sc:
                set_cookies = [x.strip() for x in sc.split(",") if "=" in x]

        if not set_cookies:
            return

        sessionish = re.compile(r"(session|sess|auth|token|jwt|csrf|xsrf)", re.I)

        for line in set_cookies:
            name = line.split("=", 1)[0].strip()
            flags = line.lower()
            is_session = bool(sessionish.search(name))
            missing = []
            if "secure" not in flags:
                missing.append("Secure")
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if "samesite" not in flags:
                missing.append("SameSite")

            if missing:
                sev = "Medium" if is_session else "Low"
                conf = "High" if is_session else "Low"
                self.add_finding(
                    severity=sev,
                    category="Cookies",
                    confidence=conf,
                    finding=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    remediation="Set Secure; HttpOnly; SameSite on session/auth cookies.",
                    evidence=line[:220],
                    http_method="GET",
                    outcome="Flags missing"
                )

    def check_cors(self, headers: Dict[str, str]):
        aco = headers.get("Access-Control-Allow-Origin", "")
        acc = headers.get("Access-Control-Allow-Credentials", "")
        if not aco:
            return
        if aco.strip() == "*" and acc.strip().lower() == "true":
            self.add_finding(
                severity="High",
                category="CORS",
                confidence="High",
                finding="CORS allows '*' with credentials enabled.",
                remediation="Do not use '*' with credentials; set explicit origins and validate per request.",
                evidence=f"ACAO={aco} | ACAC={acc}",
                http_method="GET",
                outcome="Misconfigured"
            )
        elif aco.strip() == "*":
            self.add_finding(
                severity="Medium",
                category="CORS",
                confidence="Low",
                finding="CORS allows wildcard origin '*'.",
                remediation="Prefer explicit trusted origins; avoid wildcard when not required.",
                evidence=f"ACAO={aco}",
                http_method="GET",
                outcome="Potentially permissive"
            )

    def check_tls(self):
        if self.parsed.scheme.lower() != "https":
            self.add_finding(
                severity="High",
                category="TLS",
                confidence="High",
                finding="Target is not using HTTPS.",
                remediation="Enforce HTTPS with redirects and HSTS.",
                evidence="Scheme is HTTP",
                http_method="GET",
                outcome="HTTP"
            )
            return

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    self.network.tls_version = ssock.version() or ""
                    try:
                        self.network.tls_cipher = " / ".join(ssock.cipher() or ())[:120]
                    except Exception:
                        self.network.tls_cipher = ""
                    try:
                        self.network.tls_alpn = ssock.selected_alpn_protocol() or ""
                    except Exception:
                        self.network.tls_alpn = ""

                    cert = ssock.getpeercert()
                    if cert:
                        self.network.cert_subject = str(cert.get("subject", ""))[:200]
                        self.network.cert_issuer = str(cert.get("issuer", ""))[:200]
                        na = cert.get("notAfter")
                        if na:
                            exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                            self.network.cert_days_left = (exp - datetime.datetime.utcnow()).days

                    if self.network.tls_version in ("TLSv1", "TLSv1.1", "TLSv1.0"):
                        self.add_finding(
                            severity="High",
                            category="TLS",
                            confidence="High",
                            finding=f"Weak TLS version in use: {self.network.tls_version}",
                            remediation="Require TLS 1.2+ (prefer TLS 1.3).",
                            evidence=self.network.tls_version,
                            http_method="TLS",
                            outcome="Weak"
                        )

                    if self.network.cert_days_left is not None and self.network.cert_days_left <= 30:
                        sev = "High" if self.network.cert_days_left <= 7 else "Medium"
                        self.add_finding(
                            severity=sev,
                            category="TLS",
                            confidence="High",
                            finding=f"Certificate expires soon: {self.network.cert_days_left} days left",
                            remediation="Renew certificate before expiry.",
                            evidence=f"days_left={self.network.cert_days_left}",
                            http_method="TLS",
                            outcome="Expiring"
                        )
        except Exception as e:
            self.add_finding(
                severity="Medium",
                category="TLS",
                confidence="Medium",
                finding=f"TLS inspection failed: {type(e).__name__}",
                remediation="Verify TLS configuration and connectivity.",
                evidence=str(e)[:180],
                http_method="TLS",
                outcome="Failed"
            )

    def check_robots_securitytxt(self):
        for path, label in [("/robots.txt", "robots.txt"), ("/.well-known/security.txt", "security.txt")]:
            self._sleep()
            url = urljoin(self.origin, path)
            r = self._req("GET", url)
            if not r:
                continue
            if r.status_code == 200:
                self.add_finding(
                    severity="Info",
                    category="Hardening",
                    confidence="High",
                    finding=f"{label} is accessible",
                    remediation="Review content to ensure no sensitive paths are disclosed.",
                    evidence=f"status=200 ({len(r.text)} bytes)",
                    http_method="GET",
                    outcome="Accessible"
                )

    def _signature_gate(self, path: str, content: str) -> bool:
        c = (content or "")[:4096].lower()
        if path.endswith(".env"):
            return any(k in c for k in ["db_password", "database_url", "aws_secret", "secret_key", "apikey"])
        if ".git/config" in path:
            return any(k in c for k in ["[core]", "repositoryformatversion", "[remote"])
        if "server-status" in path:
            return any(k in c for k in ["apache server status", "server uptime", "requests currently being processed"])
        return any(k in c for k in ["password", "secret", "token", "apikey"])

    def check_exposures(self):
        probes = [
            "/.env",
            "/.git/config",
            "/backup.sql",
            "/backup.zip",
            "/db.sql",
            "/server-status",
            "/config.php~",
        ]
        for path in probes:
            if self.cancel_evt.is_set():
                return
            self._sleep()
            url = urljoin(self.origin, path)

            r_head = self._req("HEAD", url)
            if not r_head:
                continue
            if r_head.status_code not in (200, 206):
                continue

            headers = {"Range": "bytes=0-4095"}
            r = self._req("GET", url, headers=headers)
            if not r:
                continue

            ct = (r.headers.get("Content-Type") or "").lower()
            body = r.text if ("text" in ct or "json" in ct or "xml" in ct or ct == "") else ""

            confirmed = self._signature_gate(path, body)
            if confirmed:
                self.add_finding(
                    severity="High" if path in ("/.env", "/.git/config") else "Medium",
                    category="Exposure",
                    confidence="High",
                    finding=f"Confirmed sensitive exposure: {path}",
                    remediation="Remove from web root; block via server rules; rotate any exposed secrets.",
                    evidence=f"status={r.status_code} ct={ct}",
                    http_method="GET",
                    outcome=f"{r.status_code}"
                )
            else:
                self.add_finding(
                    severity="Low",
                    category="Exposure",
                    confidence="Low",
                    finding=f"Potential exposure reachable but not confirmed by signatures: {path}",
                    remediation="Verify the file is not sensitive; block if unintended.",
                    evidence=f"status={r.status_code} ct={ct}",
                    http_method="GET",
                    outcome=f"{r.status_code}"
                )

    def http_matrix_check(self):
        methods_to_display = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]

        allow_hdr = ""
        self._sleep()
        ro = self._req("OPTIONS", self.target)
        if ro:
            allow_hdr = ro.headers.get("Allow", "") or ro.headers.get("allow", "")
            self.http_matrix.append(HttpMatrixItem("OPTIONS", "?", str(ro.status_code), notes=f"Allow: {allow_hdr}"[:120]))

        allowed_set = set(m.strip().upper() for m in allow_hdr.split(",") if m.strip())
        for m in methods_to_display:
            allowed = "Yes" if (m in allowed_set) else "Unknown"
            status = "—"
            notes = ""

            if m == "TRACE":
                if self.cfg.authorized_mode and self.cfg.allow_dangerous_methods:
                    self._sleep()
                    rt = self._req("TRACE", self.target)
                    if rt:
                        status = str(rt.status_code)
                        if rt.status_code == 200:
                            self.add_finding(
                                severity="High",
                                category="HTTP",
                                confidence="High",
                                finding="TRACE appears enabled (potential XST risk).",
                                remediation="Disable TRACE/TRACK at the web server / proxy.",
                                evidence=f"TRACE {rt.status_code}",
                                http_method="TRACE",
                                outcome=str(rt.status_code)
                            )
                        notes = rt.reason
                else:
                    notes = "Probe disabled (enable Authorized Mode + Dangerous Methods)"
            self.http_matrix.append(HttpMatrixItem(m, allowed, status, notes=notes))

    def broken_link_check(self, html: str):
        links: List[str] = []
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, "html.parser")  # type: ignore
                for a in soup.find_all("a", href=True):
                    href = str(a["href"]).strip()
                    if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
                        continue
                    absu = urljoin(self.target, href)
                    links.append(absu)
            except Exception:
                pass
        else:
            for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
                href = m.group(1).strip()
                if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
                    continue
                links.append(urljoin(self.target, href))

        seen = set()
        same_host_links = []
        for u in links:
            try:
                pu = urlparse(u)
                if pu.netloc and pu.netloc != self.host:
                    continue
                if u not in seen:
                    seen.add(u)
                    same_host_links.append(u)
            except Exception:
                continue

        same_host_links = same_host_links[:60]

        for u in same_host_links:
            if self.cancel_evt.is_set():
                return
            self._sleep()
            r = self._req("HEAD", u)
            if r and r.status_code < 400:
                self.broken_links.append(BrokenLinkItem(url=u, status=str(r.status_code), note="OK (HEAD)"))
                continue
            r2 = self._req("GET", u, headers={"Range": "bytes=0-512"})
            if r2:
                st = r2.status_code
                note = "OK" if st < 400 else "Broken"
                self.broken_links.append(BrokenLinkItem(url=u, status=str(st), note=note))
            else:
                self.broken_links.append(BrokenLinkItem(url=u, status="ERR", note="Request failed"))

        broken = [x for x in self.broken_links if x.status.isdigit() and int(x.status) >= 400]
        if broken:
            self.add_finding(
                severity="Low",
                category="Broken Links",
                confidence="Medium",
                finding=f"Broken links detected (same-host): {len(broken)}",
                remediation="Fix or redirect broken internal links; validate deployment routes.",
                evidence=f"checked={len(self.broken_links)} broken={len(broken)}",
                http_method="HEAD/GET",
                outcome="Some broken"
            )

    def network_diag(self):
        ips = []
        try:
            for info in socket.getaddrinfo(self.host, None):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        self.network.dns_ips = ips[:6]
        self.network.ipv6_present = any(":" in x for x in ips)

        def rtt(port: int) -> Optional[int]:
            try:
                t0 = time.time()
                s = socket.create_connection((self.host, port), timeout=4)
                s.close()
                return int((time.time() - t0) * 1000)
            except Exception:
                return None

        self.network.rtt_80_ms = rtt(80)
        self.network.rtt_443_ms = rtt(443) if self.parsed.scheme.lower() == "https" else None

    # ─────────────────────────────────────────
    # NEW: Advanced network diagnostics (NOT port scanning)
    # ─────────────────────────────────────────
    def advanced_network_diagnostics(self):
        # HTTP -> HTTPS redirect check (best-effort)
        try:
            http_url = f"http://{self.host}/"
            self._sleep()
            r = self._req("GET", http_url, allow_redirects=False, verify=False, timeout=10)
            if r is not None:
                loc = (r.headers.get("Location") or "").lower()
                if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                    self.network.http_redirect_to_https = True
                else:
                    self.network.http_redirect_to_https = False
        except Exception:
            self.network.http_redirect_to_https = None

        # Add an informational finding
        if self.network.http_redirect_to_https is True:
            self.add_finding(
                severity="Info",
                category="Network",
                confidence="High",
                finding="HTTP appears to redirect to HTTPS (good).",
                remediation="Keep HTTP redirect enabled; pair with HSTS for strict enforcement.",
                evidence="http -> https redirect",
                http_method="GET",
                outcome="Redirect"
            )
        elif self.network.http_redirect_to_https is False:
            self.add_finding(
                severity="Medium",
                category="Network",
                confidence="Low",
                finding="HTTP does not clearly redirect to HTTPS (best-effort).",
                remediation="Ensure HTTP redirects to HTTPS and enable HSTS (where applicable).",
                evidence="no redirect observed",
                http_method="GET",
                outcome="No redirect"
            )

    # ─────────────────────────────────────────
    # NEW: WAF detection (no bypass; hardening only)
    # ─────────────────────────────────────────
    def waf_detect(self, headers: Dict[str, str], body: str):
        h = {k.lower(): (v or "") for k, v in (headers or {}).items()}
        sigs = [
            ("Cloudflare", lambda: "cf-ray" in h or "cloudflare" in (h.get("server", "").lower())),
            ("Akamai", lambda: "akamai" in (h.get("server", "").lower()) or "akamai" in (h.get("x-akamai-transformed", "").lower())),
            ("Imperva/Incapsula", lambda: "incap_ses" in (h.get("set-cookie", "").lower()) or "imperva" in (h.get("server", "").lower())),
            ("F5", lambda: "bigip" in (h.get("set-cookie", "").lower()) or "f5" in (h.get("server", "").lower())),
            ("Radware", lambda: "radware" in (h.get("server", "").lower()) or "x-rdwr" in "".join(h.keys())),
            ("Sucuri", lambda: "sucuri" in (h.get("server", "").lower()) or "x-sucuri-id" in h),
        ]
        detected = []
        for name, fn in sigs:
            try:
                if fn():
                    detected.append(name)
            except Exception:
                pass

        self.discovery.setdefault("waf", detected or ["Unknown"])

        if detected:
            self.add_finding(
                severity="Info",
                category="WAF",
                confidence="High",
                finding=f"WAF/CDN fingerprinted: {', '.join(detected)}",
                remediation="Validate OWASP rules coverage, tune false positives, and ensure WAF logs feed SIEM/SOAR with alerting.",
                evidence="; ".join(detected)[:180],
                http_method="GET",
                outcome="Detected"
            )
        else:
            self.add_finding(
                severity="Info",
                category="WAF",
                confidence="Low",
                finding="No obvious WAF/CDN fingerprint detected from headers (best-effort).",
                remediation="If a WAF exists, ensure security headers/events are not stripped and logs are centralized.",
                evidence="signature not found",
                http_method="GET",
                outcome="Unknown"
            )

    # ─────────────────────────────────────────
    # NEW: JavaScript secret scanner (masked output)
    # ─────────────────────────────────────────
    def js_secret_scan(self, html: str):
        scripts = extract_script_srcs(html)
        js_urls = []
        for s in scripts:
            u = urljoin(self.target, s)
            pu = urlparse(u)
            if pu.netloc and pu.netloc != self.host:
                continue  # same-host only
            js_urls.append(u)

        js_urls = list(dict.fromkeys(js_urls))[: self.cfg.js_max_files]
        found = []

        patterns = [
            ("AWS Access Key", re.compile(r"\b(AKIA|ASIA|AIDA|AROA|AGPA|ANPA)[A-Z0-9]{16}\b")),
            ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
            ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
            ("Stripe Secret Key", re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{16,}\b")),
            ("JWT (possible)", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
            ("Generic API Key (weak)", re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*[\"']([^\"']{12,})[\"']")),
        ]

        for u in js_urls:
            if self.cancel_evt.is_set():
                return
            self._sleep()
            r = self._req("GET", u, headers={"Range": f"bytes=0-{self.cfg.js_max_bytes}"})
            if not r or r.status_code >= 400:
                continue
            txt = r.text or ""
            for label, rx in patterns:
                for m in rx.finditer(txt):
                    raw = m.group(0)
                    if label.startswith("Generic") and m.lastindex and m.lastindex >= 2:
                        raw = m.group(2)
                    found.append({"type": label, "file": u, "value": mask_secret(raw)})

            if len(found) > 30:
                break

        self.discovery["js_secrets"] = found

        if found:
            hi_types = {"AWS Access Key", "Google API Key", "Slack Token", "Stripe Secret Key"}
            hi = any(x["type"] in hi_types for x in found)
            self.add_finding(
                severity="High" if hi else "Medium",
                category="Secrets",
                confidence="Medium",
                finding=f"Potential secrets detected in JavaScript assets (masked): {len(found)} indicator(s).",
                remediation="Remove secrets from client-side code. Rotate exposed keys immediately. Use server-side token brokerage and secret managers.",
                evidence=f"{found[0]['type']} in {found[0]['file']} -> {found[0]['value']}"[:200],
                http_method="GET",
                outcome="Indicators"
            )
        else:
            self.add_finding(
                severity="Info",
                category="Secrets",
                confidence="High",
                finding="JavaScript secret scan completed (same-host scripts). No obvious key patterns found (best-effort).",
                remediation="Enforce secret detection in CI/CD and pre-commit hooks; rotate keys periodically.",
                evidence=f"checked_js={len(js_urls)}",
                http_method="GET",
                outcome="Clean"
            )

    # ─────────────────────────────────────────
    # NEW: Subdomain enumeration (PASSIVE: crt.sh)
    # ─────────────────────────────────────────
    def subdomain_enum(self):
        bd = base_domain(self.host)
        subs = set()

        try:
            self._sleep()
            url = f"https://crt.sh/?q=%25.{bd}&output=json"
            r = self._req("GET", url)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    for row in data[:2000]:
                        nv = str(row.get("name_value", ""))
                        for line in nv.splitlines():
                            s = line.strip().lower().lstrip("*.")  # strip wildcard
                            if s.endswith("." + bd) or s == bd:
                                subs.add(s)
                except Exception:
                    pass
        except Exception:
            pass

        all_subs = sorted(list(subs))[:200]
        self.discovery["subdomains"] = all_subs

        self.add_finding(
            severity="Info",
            category="Discovery",
            confidence="Medium",
            finding=f"Passive subdomain discovery found {len(all_subs)} hostnames for '{bd}' (best-effort).",
            remediation="Validate ownership, remove stale DNS, enforce consistent TLS/WAF/auth controls across exposed subdomains.",
            evidence=", ".join(all_subs[:10])[:200] if all_subs else "—",
            http_method="Passive",
            outcome="Enumerated"
        )

    # ─────────────────────────────────────────
    # NEW: Cloud storage discovery (passive + HEAD check)
    # ─────────────────────────────────────────
    def cloud_storage_discovery(self, html: str):
        refs = find_cloud_refs(html or "")
        self.discovery["cloud_refs"] = refs

        total = sum(len(v) for v in refs.values())
        if total == 0:
            self.add_finding(
                severity="Info",
                category="Cloud Storage",
                confidence="High",
                finding="No obvious cloud storage URLs referenced in initial HTML (best-effort).",
                remediation="If storage is used, enforce private-by-default, signed URLs, and logging.",
                evidence="no refs found",
                http_method="GET",
                outcome="None"
            )
            return

        public_hits = []
        for kind, urls in refs.items():
            for u in urls[:15]:
                if self.cancel_evt.is_set():
                    return
                self._sleep()
                r = self._req("HEAD", u)
                if r and r.status_code in (200, 206, 301, 302):
                    public_hits.append((kind, u, r.status_code))

        if public_hits:
            self.add_finding(
                severity="Medium",
                category="Cloud Storage",
                confidence="Medium",
                finding=f"Referenced cloud storage objects reachable without auth (HEAD success): {len(public_hits)}",
                remediation="Review access policies; block public ACLs, enforce least privilege, use signed URLs, and enable access logging.",
                evidence=f"{public_hits[0][0]} {public_hits[0][2]} {public_hits[0][1]}"[:200],
                http_method="HEAD",
                outcome="Reachable"
            )
        else:
            self.add_finding(
                severity="Info",
                category="Cloud Storage",
                confidence="Medium",
                finding=f"Cloud storage references detected ({total}), but no public access confirmed via HEAD (best-effort).",
                remediation="Maintain guardrails: block public access, monitor policy drift, and run periodic CSPM checks.",
                evidence=f"refs={total}",
                http_method="HEAD",
                outcome="Not confirmed"
            )

    # ─────────────────────────────────────────
    # NEW: GraphQL discovery & safe testing
    # ─────────────────────────────────────────
    def graphql_discovery(self):
        candidates = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]
        found = []

        for pth in candidates:
            if self.cancel_evt.is_set():
                return
            self._sleep()
            url = urljoin(self.origin, pth)
            payload = {"query": "{__typename}"}
            r = self._req("POST", url, json=payload, headers={"Content-Type": "application/json"})
            if not r:
                continue
            if r.status_code in (200, 400, 401, 403):
                try:
                    j = r.json()
                    if isinstance(j, dict) and ("data" in j or "errors" in j):
                        found.append({"endpoint": url, "status": r.status_code, "signals": list(j.keys())})
                except Exception:
                    if "graphql" in (r.text or "").lower():
                        found.append({"endpoint": url, "status": r.status_code, "signals": ["html"]})

        self.discovery["graphql"] = found

        if found:
            sev = "Medium" if any(x["status"] == 200 for x in found) else "Info"
            self.add_finding(
                severity=sev,
                category="GraphQL",
                confidence="Medium",
                finding=f"GraphQL endpoint(s) discovered: {len(found)} (safe probe).",
                remediation="Harden GraphQL: disable introspection in prod, enforce auth on resolvers, apply depth/complexity limits, and rate-limit.",
                evidence=f"{found[0]['endpoint']} status={found[0]['status']}"[:200],
                http_method="POST",
                outcome="Discovered"
            )
        else:
            self.add_finding(
                severity="Info",
                category="GraphQL",
                confidence="High",
                finding="No GraphQL endpoints detected using safe probes (best-effort).",
                remediation="If GraphQL exists elsewhere, ensure auth, query limits, and logging are enabled.",
                evidence="candidates probed",
                http_method="POST",
                outcome="Not found"
            )

    # ─────────────────────────────────────────
    # NEW: WebSocket detection
    # ─────────────────────────────────────────
    def websocket_detect(self, html: str):
        refs = find_ws_refs(html or "")
        self.discovery["websockets"] = refs
        if refs:
            self.add_finding(
                severity="Info",
                category="WebSocket",
                confidence="Medium",
                finding=f"WebSocket references detected (ws/wss): {len(refs)}",
                remediation="Enforce WSS only, authenticate socket handshake, validate Origin, and apply message rate limits.",
                evidence=", ".join(refs[:3])[:200],
                http_method="GET",
                outcome="Detected"
            )
        else:
            self.add_finding(
                severity="Info",
                category="WebSocket",
                confidence="High",
                finding="No WebSocket references detected in initial HTML (best-effort).",
                remediation="If used dynamically, ensure WSS + auth + origin checks + monitoring.",
                evidence="no refs found",
                http_method="GET",
                outcome="None"
            )

    # ─────────────────────────────────────────
    # NEW: Rate limiting test (small, gated)
    # ─────────────────────────────────────────
    def rate_limit_test(self):
        if not self.cfg.authorized_mode:
            self.add_finding(
                severity="Info",
                category="Rate Limiting",
                confidence="High",
                finding="Rate limiting burst test skipped (Authorized Mode is OFF).",
                remediation="Enable Authorized Mode to run a small burst test safely.",
                evidence="authorized_mode=false",
                http_method="GET",
                outcome="Skipped"
            )
            return

        n = max(6, min(20, int(self.cfg.rate_limit_burst)))
        hits_429 = 0
        statuses = []

        t0 = time.time()
        for _ in range(n):
            if self.cancel_evt.is_set():
                break
            r = self._req("GET", self.target, headers={"Cache-Control": "no-cache"}, timeout=10)
            if not r:
                statuses.append("ERR")
            else:
                statuses.append(str(r.status_code))
                if r.status_code == 429:
                    hits_429 += 1
            time.sleep(0.05)

        dt = max(0.001, time.time() - t0)
        rps = round(n / dt, 2)

        self.discovery["rate_limit"] = {"burst": n, "rps": rps, "hits_429": hits_429, "sample_statuses": statuses[:12]}

        if hits_429 > 0:
            self.add_finding(
                severity="Info",
                category="Rate Limiting",
                confidence="Medium",
                finding=f"Rate limiting appears present (HTTP 429 observed). Burst={n}, approx RPS={rps}",
                remediation="Confirm consistent throttling on auth endpoints and APIs. Monitor for bot/credential stuffing.",
                evidence=f"429_hits={hits_429} sample={','.join(statuses[:10])}",
                http_method="GET",
                outcome="Throttled"
            )
        else:
            self.add_finding(
                severity="Medium",
                category="Rate Limiting",
                confidence="Low",
                finding=f"No obvious throttling detected in small burst test (no 429). Burst={n}, approx RPS={rps}",
                remediation="Implement rate limiting per IP/user/endpoint (especially login/OTP/API). Add WAF bot rules and anomaly detection.",
                evidence=f"sample={','.join(statuses[:10])}",
                http_method="GET",
                outcome="No 429"
            )

    # ─────────────────────────────────────────
    # NEW: Real-time CVE intelligence (best-effort via CIRCL search)
    # ─────────────────────────────────────────
    def cve_intelligence(self, headers: Dict[str, str], body: str):
        tech = []
        server = (headers.get("Server") or "").strip()
        xpb = (headers.get("X-Powered-By") or "").strip()

        def add_tech(src: str):
            src = (src or "").strip()
            if not src:
                return
            # split banner like nginx/1.20.1
            if "/" in src:
                name, ver = src.split("/", 1)
                tech.append({"name": name.strip(), "version": ver.split()[0].strip()})
            else:
                tech.append({"name": src, "version": ""})

        add_tech(server)
        add_tech(xpb)

        # meta generator hint
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body or "", re.I)
        if m:
            tech.append({"name": "generator", "version": m.group(1)[:64]})

        # de-dup + cap
        uniq = {}
        for t in tech:
            key = (t["name"].lower(), t["version"])
            uniq[key] = t
        tech = list(uniq.values())[:8]
        self.discovery["tech"] = tech

        intel = []
        queries = 0

        for t in tech:
            name = t["name"]
            if name.lower() in ("generator",):
                continue
            q = name.split()[0].lower()
            if not q or len(q) < 2:
                continue
            queries += 1
            if queries > self.cfg.cve_max_queries:
                break
            try:
                self._sleep()
                r = self._req("GET", f"https://cve.circl.lu/api/search/{q}", timeout=12)
                if r and r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
                        items = data["data"][:5]
                        intel.append({
                            "query": q,
                            "top": [
                                {"id": i.get("id"), "cvss": i.get("cvss"), "summary": (i.get("summary") or "")[:140]}
                                for i in items
                            ]
                        })
            except Exception:
                continue

        self.cve_intel = intel

        if intel:
            self.add_finding(
                severity="Info",
                category="CVE Intel",
                confidence="Low",
                finding=f"Real-time CVE intelligence retrieved for {len(intel)} keyword(s) (best-effort).",
                remediation="Confirm exact product/version via authenticated inventory or SBOM; patch/mitigate prioritized CVEs.",
                evidence=f"sample={intel[0]['query']} {intel[0]['top'][0]['id'] if intel[0]['top'] else ''}"[:200],
                http_method="GET",
                outcome="Retrieved"
            )
        else:
            self.add_finding(
                severity="Info",
                category="CVE Intel",
                confidence="Medium",
                finding="CVE intelligence not retrieved (no banner match or external API unreachable).",
                remediation="Provide tech stack + versions (Server/framework/CMS) to enrich CVE mapping, or run from allowlisted network.",
                evidence=f"tech_detected={len(tech)}",
                http_method="GET",
                outcome="Empty"
            )

    # ─────────────────────────────────────────
    # NEW: OWASP / PCI / ISO mapping + AI recommendations + history
    # ─────────────────────────────────────────
    def build_compliance_and_reco(self):
        if not (self.cfg.mod_compliance or self.cfg.mod_ai_reco):
            self.compliance = {}
            self.recommendations = []
            return

        owasp_map = {
            "TLS": "A02: Cryptographic Failures",
            "Cookies": "A07: Identification & Authentication Failures",
            "CORS": "A05: Security Misconfiguration",
            "Headers": "A05: Security Misconfiguration",
            "Exposure": "A05: Security Misconfiguration",
            "Clickjacking": "A05: Security Misconfiguration",
            "HTTP": "A05: Security Misconfiguration",
            "Secrets": "A02: Cryptographic Failures",
            "GraphQL": "A04: Insecure Design",
            "Rate Limiting": "A07: Identification & Authentication Failures",
            "Network": "A05: Security Misconfiguration",
        }

        pci = []
        iso = []
        owasp = []

        if self.cfg.mod_compliance:
            for f in self.findings:
                if f.category in owasp_map:
                    owasp.append(f"{owasp_map[f.category]} — {f.category}: {f.finding}")

                if f.category == "TLS":
                    pci.append("PCI DSS Req 4 — Strong cryptography for transmission (TLS 1.2+).")
                    iso.append("ISO 27001 (best-effort) — Cryptography & secure communications controls.")
                if f.category in ("Exposure", "Headers", "CORS", "Clickjacking"):
                    pci.append("PCI DSS Req 6 — Secure systems and applications (hardening & secure configuration).")
                    iso.append("ISO 27001 (best-effort) — Secure configuration & network security controls.")
                if f.category == "Secrets":
                    pci.append("PCI DSS Req 3/6 — Protect sensitive auth data; remove secrets from client-side code.")
                    iso.append("ISO 27001 (best-effort) — Secure development & secret management controls.")
                if f.category == "Rate Limiting":
                    pci.append("PCI DSS Req 8 — Reduce brute-force risk (rate limiting / lockout).")
                    iso.append("ISO 27001 (best-effort) — Access control & protective monitoring controls.")

            self.compliance = {
                "OWASP Top 10 Mapping": list(dict.fromkeys(owasp))[:20],
                "PCI DSS Gap Indicators": list(dict.fromkeys(pci))[:12],
                "ISO 27001 Control Mapping": list(dict.fromkeys(iso))[:12],
            }

        # AI-style recommendations (rule-based)
        recos = []
        if self.cfg.mod_ai_reco:
            if any(f.category == "TLS" and f.severity in ("High", "Medium") for f in self.findings):
                recos.append("Enforce TLS 1.2+ (prefer TLS 1.3), renew expiring certs, and enable HSTS.")
            if any(f.category == "Exposure" and f.severity in ("High", "Medium") for f in self.findings):
                recos.append("Remove exposed artifacts from webીroot (.env/.git/backups), block via server rules, and rotate any exposed secrets.")
            if any(f.category in ("Headers", "Clickjacking", "CORS") and f.severity in ("High", "Medium") for f in self.findings):
                recos.append("Apply baseline hardening: CSP, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy, and strict CORS allowlists.")
            if any(f.category == "Secrets" and f.severity in ("High", "Medium") for f in self.findings):
                recos.append("Rotate any exposed keys, move secrets server-side, and enforce secret scanning in CI/CD (pre-commit + pipeline gates).")
            if self.cfg.authorized_mode and any(f.category == "Rate Limiting" and f.severity in ("High", "Medium") for f in self.findings):
                recos.append("Confirm rate limits on login/OTP/API endpoints and enable bot/credential-stuffing protections.")
            if self.network.http_redirect_to_https is False:
                recos.append("Redirect HTTP → HTTPS and enable HSTS to prevent downgrade and mixed-content risks.")

            # Always include a governance line
            recos.append("Enable continuous monitoring: WAF/SIEM alerts, vulnerability management SLAs, and change-control review for security headers and TLS.")

        self.recommendations = recos[:10]

    def update_history(self, res_summary: Dict[str, Any]):
        if not self.cfg.mod_history:
            self.history = {}
            return

        path = self.cfg.history_path.strip()
        if not path:
            path = os.path.join(os.path.expanduser("~"), ".nightfall_tsukuyomi_history.json")

        hist = {"runs": []}
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    hist = json.load(f) or {"runs": []}
        except Exception:
            hist = {"runs": []}

        runs = hist.get("runs", [])
        last = runs[-1] if runs else None

        runs.append(res_summary)
        hist["runs"] = runs[-30:]

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(hist, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        if last:
            try:
                dscore = int(res_summary.get("risk_score", 0)) - int(last.get("risk_score", 0))
                self.history = {"history_path": path, "delta_risk": dscore, "previous": last}
            except Exception:
                self.history = {"history_path": path}
        else:
            self.history = {"history_path": path, "delta_risk": None}

    def compute_risk(self) -> int:
        weights = {"Critical": 22, "High": 14, "Medium": 8, "Low": 3, "Info": 1}
        score = 0.0
        for f in self.findings:
            w = weights.get(f.severity, 0)
            score += w * CONF_MULT.get(f.confidence, 0.8)
        score = 100.0 * (1.0 - math.exp(-score / 55.0))
        return int(max(0, min(100, round(score))))

    def run(self) -> ScanResult:
        started = time.time()
        self.log(f"[init] NIGHTFALL TSUKUYOMI — target: {self.target}")

        self.progress(5, "Connecting to target...")
        self._sleep()
        r = self._req("GET", self.target)
        if not r:
            self.add_finding(
                severity="High",
                category="Connectivity",
                confidence="High",
                finding="Target is not reachable (request failed).",
                remediation="Check DNS, connectivity, and allowlisting. Retry with correct URL.",
                evidence="requests failed",
                http_method="GET",
                outcome="Failed"
            )
        else:
            self.log(f"[ok] GET {r.status_code} {self.target}")
            headers = dict(r.headers)

            steps = []
            if self.cfg.mod_headers:
                steps.append(("Checking headers / disclosure...", lambda: self.check_headers(headers)))
            if self.cfg.mod_clickjacking:
                steps.append(("Checking clickjacking...", lambda: self.check_clickjacking(headers)))
            if self.cfg.mod_cors:
                steps.append(("Checking CORS...", lambda: self.check_cors(headers)))
            if self.cfg.mod_cookies:
                steps.append(("Checking cookie flags...", lambda: self.check_cookies(r)))
            if self.cfg.mod_tls:
                steps.append(("Inspecting TLS...", self.check_tls))
            if self.cfg.mod_http_matrix:
                steps.append(("HTTP Matrix (OPTIONS + safe probes)...", self.http_matrix_check))
            if self.cfg.mod_exposures:
                steps.append(("Exposure probes (signature gated)...", self.check_exposures))
            if self.cfg.mod_robots_securitytxt:
                steps.append(("robots.txt / security.txt...", self.check_robots_securitytxt))
            if self.cfg.mod_broken_links:
                steps.append(("Broken links (same-host)...", lambda: self.broken_link_check(r.text)))
            if self.cfg.mod_network:
                steps.append(("Network diagnostics (DNS + 80/443 RTT)...", self.network_diag))

            # NEW requested capabilities
            if self.cfg.mod_adv_network:
                steps.append(("Advanced network diagnostics (redirect/TLS ALPN)...", self.advanced_network_diagnostics))
            if self.cfg.mod_waf_detect:
                steps.append(("WAF detection (fingerprint + hardening)...", lambda: self.waf_detect(headers, r.text)))
            if self.cfg.mod_js_secrets:
                steps.append(("JavaScript Secret Scanner (masked)...", lambda: self.js_secret_scan(r.text)))
            if self.cfg.mod_subdomains:
                steps.append(("Subdomain Enumeration (passive CT logs)...", self.subdomain_enum))
            if self.cfg.mod_cloud_storage:
                steps.append(("Cloud Storage Scanner (AWS/Azure/GCP refs)...", lambda: self.cloud_storage_discovery(r.text)))
            if self.cfg.mod_graphql:
                steps.append(("GraphQL API Discovery & Testing (safe)...", self.graphql_discovery))
            if self.cfg.mod_websocket:
                steps.append(("WebSocket Detection...", lambda: self.websocket_detect(r.text)))
            if self.cfg.mod_rate_limit:
                steps.append(("Rate Limiting Tests (authorized burst)...", self.rate_limit_test))
            if self.cfg.mod_cve_intel:
                steps.append(("Real-time CVE Intelligence (best-effort)...", lambda: self.cve_intelligence(headers, r.text)))

            total = len(steps)
            for i, (msg, fn) in enumerate(steps, start=1):
                if self.cancel_evt.is_set():
                    break
                self.progress(5 + int(90 * (i / max(1, total))), msg)
                self.log(f"[scan] {msg}")
                try:
                    fn()
                except Exception as e:
                    self.log(f"[warn] module error: {type(e).__name__}")

        self.findings.sort(key=lambda x: (SEV_ORDER.get(x.severity, 99), x.category))

        # Build compliance + recommendations (AI-style)
        self.build_compliance_and_reco()

        # Compute risk
        score = self.compute_risk()
        grade, _ = risk_band(score)

        # History
        self.update_history({
            "ts": now_iso(),
            "target": self.target,
            "risk_score": score,
            "findings": len(self.findings),
            "high_crit": sum(1 for f in self.findings if f.severity in ("High", "Critical"))
        })

        dur = time.time() - started
        self.progress(100, "Complete.")
        self.log(f"[done] duration={dur:.2f}s risk={score}/100 ({grade}) requests={self.req_ok}/{self.req_total}")

        return ScanResult(
            target=self.target,
            started_at=now_iso(),
            duration_s=round(dur, 2),
            risk_score=score,
            risk_grade=grade,
            requests_ok=self.req_ok,
            requests_total=self.req_total,
            findings=self.findings,
            http_matrix=self.http_matrix,
            broken_links=self.broken_links,
            network=self.network,
            discovery=self.discovery,
            cve_intel=self.cve_intel,
            compliance=self.compliance,
            recommendations=self.recommendations,
            history=self.history,
        )


# ──────────────────────────────────────────────────────────────────────────────
# WORKER (thread)
# ──────────────────────────────────────────────────────────────────────────────
class ScanWorker(QObject):
    finished = pyqtSignal(object)
    progress = pyqtSignal(int, str)
    log = pyqtSignal(str)

    def __init__(self, target: str, cfg: ScanConfig, auth: AuthConfig, cancel_evt: threading.Event):
        super().__init__()
        self.target = target
        self.cfg = cfg
        self.auth = auth
        self.cancel_evt = cancel_evt

    def run(self):
        scanner = NightfallScanner(
            target=self.target,
            cfg=self.cfg,
            auth=self.auth,
            cancel_evt=self.cancel_evt,
            log_fn=lambda s: self.log.emit(s),
            progress_fn=lambda p, m: self.progress.emit(p, m),
        )
        result = scanner.run()
        self.finished.emit(result)


# ──────────────────────────────────────────────────────────────────────────────
# PDF EXPORT (reportlab)
# ──────────────────────────────────────────────────────────────────────────────
def _try_register_unicode_font() -> str:
    if not HAS_REPORTLAB:
        return "Helvetica"

    candidates = [
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibri.ttf",
    ]
    for path in candidates:
        try:
            pdfmetrics.registerFont(TTFont("NFU", path))  # type: ignore
            return "NFU"
        except Exception:
            continue
    return "Helvetica"


def export_pdf(path: str, res: ScanResult):
    if not HAS_REPORTLAB:
        raise RuntimeError("reportlab not installed. pip install reportlab")

    font_name = _try_register_unicode_font()

    styles = getSampleStyleSheet()
    base = ParagraphStyle(
        "base",
        parent=styles["Normal"],
        fontName=font_name,
        fontSize=10,
        leading=13,
        textColor=colors.whitesmoke,
    )
    h1 = ParagraphStyle(
        "h1",
        parent=styles["Heading1"],
        fontName=font_name,
        fontSize=16,
        leading=18,
        textColor=colors.cyan,
        spaceAfter=10,
    )
    h2 = ParagraphStyle(
        "h2",
        parent=styles["Heading2"],
        fontName=font_name,
        fontSize=12,
        leading=14,
        textColor=colors.HexColor("#A855F7"),
        spaceBefore=10,
        spaceAfter=6,
    )

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm
    )

    story = []

    def P(txt: str, st=base):
        story.append(Paragraph(sanitize_pdf_text(txt), st))

    def SP(h=8):
        story.append(Spacer(1, h))

    P("NIGHTFALL TSUKUYOMI — Web Security Audit Report", h1)
    band, _c = risk_band(res.risk_score)
    P(f"Target: {res.target}")
    P(f"Started: {res.started_at}  |  Duration: {res.duration_s}s")
    P(f"Requests: {res.requests_ok}/{res.requests_total} OK")
    P(f"Risk: {res.risk_score}/100 ({band})")
    if res.history and res.history.get("delta_risk") is not None:
        P(f"History Delta Risk: {res.history.get('delta_risk'):+d} (vs previous run)")
    SP(10)

    P("Executive Summary", h2)
    summary_data = [
        ["Metric", "Value"],
        ["Risk Score", f"{res.risk_score}/100 ({band})"],
        ["Total Findings", str(len(res.findings))],
        ["High/Critical", str(sum(1 for f in res.findings if f.severity in ("High", "Critical")))],
        ["Medium", str(sum(1 for f in res.findings if f.severity == "Medium"))],
        ["Low/Info", str(sum(1 for f in res.findings if f.severity in ("Low", "Info")))],
    ]
    tbl = Table(summary_data, colWidths=[60 * mm, 110 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111024")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.cyan),
        ("FONTNAME", (0, 0), (-1, 0), font_name),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#080616")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#35265a")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)
    SP(10)

    P("Findings", h2)
    fdata = [["Sev", "Category", "Finding", "Remediation", "Confidence", "HTTP/Outcome"]]
    for f in res.findings[:120]:
        fdata.append([
            f.severity,
            f.category,
            sanitize_pdf_text(f.finding),
            sanitize_pdf_text(f.remediation),
            f.confidence,
            sanitize_pdf_text(f"{f.http_method} {f.outcome}".strip()),
        ])
    ftbl = Table(fdata, colWidths=[16 * mm, 26 * mm, 55 * mm, 55 * mm, 22 * mm, 26 * mm])
    ftbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111024")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.cyan),
        ("FONTNAME", (0, 0), (-1, 0), font_name),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#35265a")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#080616")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.whitesmoke),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(ftbl)
    SP(10)

    P("Network Diagnostics", h2)
    nd = res.network
    P(f"DNS IPs: {', '.join(nd.dns_ips) if nd.dns_ips else '—'}")
    P(f"IPv6 Present: {'Yes' if nd.ipv6_present else 'No'}")
    P(f"RTT 80: {nd.rtt_80_ms if nd.rtt_80_ms is not None else '—'} ms")
    P(f"RTT 443: {nd.rtt_443_ms if nd.rtt_443_ms is not None else '—'} ms")
    P(f"HTTP → HTTPS Redirect: {('Yes' if nd.http_redirect_to_https else 'No') if nd.http_redirect_to_https is not None else '—'}")
    P(f"TLS Version: {nd.tls_version or '—'}")
    if nd.tls_alpn:
        P(f"ALPN: {nd.tls_alpn}")
    if nd.tls_cipher:
        P(f"Cipher: {nd.tls_cipher}")
    if nd.cert_days_left is not None:
        P(f"Cert Days Left: {nd.cert_days_left}")
    SP(8)

    if res.recommendations:
        P("AI-Powered Analysis & Recommendations", h2)
        for i, rline in enumerate(res.recommendations[:10], 1):
            P(f"{i}. {rline}")
        SP(8)

    if res.cve_intel:
        P("Real-time CVE Intelligence (Best-effort)", h2)
        for block in res.cve_intel[:5]:
            q = block.get("query", "—")
            P(f"Keyword: {q}")
            for item in (block.get("top") or [])[:5]:
                P(f"- {item.get('id', '—')} | CVSS: {item.get('cvss', '—')} | {item.get('summary', '')}")
            SP(6)

    if res.compliance:
        P("Compliance Mapping (OWASP / PCI DSS / ISO 27001)", h2)
        for k, lines in res.compliance.items():
            P(k, h2)
            for ln in (lines or [])[:20]:
                P(f"- {ln}")
            SP(6)

    if res.discovery:
        P("Discovery & Asset Intelligence", h2)
        P(f"Subdomains: {len((res.discovery.get('subdomains') or []))}")
        P(f"WebSockets: {len((res.discovery.get('websockets') or []))}")
        P(f"GraphQL endpoints: {len((res.discovery.get('graphql') or []))}")
        cloud = res.discovery.get("cloud_refs") or {}
        P(f"Cloud refs: S3={len(cloud.get('aws_s3', []))} Azure={len(cloud.get('azure_blob', []))} GCP={len(cloud.get('gcp_storage', []))}")
        waf = res.discovery.get("waf") or []
        P(f"WAF/CDN: {', '.join(waf) if waf else '—'}")
        SP(6)

    P("Disclaimer: Authorized testing only. Findings are best-effort indicators; validate before remediation.", base)
    doc.build(story)


# ──────────────────────────────────────────────────────────────────────────────
# UI
# ──────────────────────────────────────────────────────────────────────────────
class NightfallTsukuyomiApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NIGHTFALL TSUKUYOMI")
        self.setMinimumSize(1600, 900)

        self.cfg = ScanConfig()
        self.auth = AuthConfig()
        self.current: Optional[ScanResult] = None

        self._cancel_evt = threading.Event()
        self._thread: Optional[QThread] = None
        self._worker: Optional[ScanWorker] = None

        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        root_l = QVBoxLayout(root)
        root_l.setContentsMargins(14, 12, 14, 12)
        root_l.setSpacing(10)

        title = QLabel("NIGHTFALL TSUKUYOMI")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: 900; letter-spacing: 3px; color: #00E5FF;")
        root_l.addWidget(title)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_scanner(), "Scanner")
        self.tabs.addTab(self._tab_findings(), "Findings")
        self.tabs.addTab(self._tab_intel(), "Intel")
        self.tabs.addTab(self._tab_http_matrix(), "HTTP Matrix")
        self.tabs.addTab(self._tab_broken_links(), "Broken Links")
        self.tabs.addTab(self._tab_network(), "Network")
        self.tabs.addTab(self._tab_settings(), "Settings")
        root_l.addWidget(self.tabs)

        self.setCentralWidget(root)

        self.status = self.statusBar()
        self.status.showMessage("Idle.")

    # ───────────── TAB 1: Scanner ─────────────
    def _tab_scanner(self) -> QWidget:
        w = QWidget()
        grid = QGridLayout(w)
        grid.setContentsMargins(6, 6, 6, 6)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)

        self.card_risk = HudCard("RISK SCORE")
        self.card_req = HudCard("REQUESTS")
        self.card_status = HudCard("OPERATOR STATUS")
        self.gauge = RiskGauge()

        self.card_risk.set_value("—/100", "—")
        self.card_req.set_value("—", "RTT: —")
        self.card_status.set_value("IDLE", "Awaiting execute.", QColor("#93C5FD"))
        self.gauge.set_score(0)

        hud = QGridLayout()
        hud.setHorizontalSpacing(10)
        hud.addWidget(self.card_risk, 0, 0)
        hud.addWidget(self.card_req, 0, 1)
        hud.addWidget(self.card_status, 0, 2)
        hud.addWidget(self.gauge, 0, 3)
        hud.setColumnStretch(0, 2)
        hud.setColumnStretch(1, 2)
        hud.setColumnStretch(2, 2)
        hud.setColumnStretch(3, 1)

        hud_wrap = card_frame()
        hud_wrap_l = QVBoxLayout(hud_wrap)
        hud_wrap_l.setContentsMargins(10, 10, 10, 10)
        hud_wrap_l.addLayout(hud)
        grid.addWidget(hud_wrap, 0, 0, 1, 3)

        left = QVBoxLayout()
        left.setSpacing(10)

        gb_target = QGroupBox("TARGET")
        fl = QFormLayout(gb_target)
        self.in_url = QLineEdit("https://")
        self.in_profile = QComboBox()
        self.in_profile.addItems(["Safe", "Extended", "Aggressive"])
        fl.addRow("URL", self.in_url)
        fl.addRow("HTTP Profile", self.in_profile)
        left.addWidget(gb_target)

        gb_ops = QGroupBox("OPERATIONS")
        ops = QVBoxLayout(gb_ops)
        btns = QHBoxLayout()
        self.btn_exec = QPushButton("Execute")
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_pdf = QPushButton("Export PDF")
        self.btn_json = QPushButton("Export JSON")
        btns.addWidget(self.btn_exec)
        btns.addWidget(self.btn_stop)
        ops.addLayout(btns)
        ops.addWidget(self.btn_pdf)
        ops.addWidget(self.btn_json)

        self.prog = QProgressBar()
        self.prog.setValue(0)
        ops.addWidget(self.prog)

        left.addWidget(gb_ops)
        left.addStretch(1)

        left_wrap = card_frame()
        left_wrap_l = QVBoxLayout(left_wrap)
        left_wrap_l.setContentsMargins(10, 10, 10, 10)
        left_wrap_l.addLayout(left)
        grid.addWidget(left_wrap, 1, 0, 2, 1)

        center_wrap = card_frame()
        center_l = QVBoxLayout(center_wrap)
        center_l.setContentsMargins(10, 10, 10, 10)
        tl = QLabel("TARGET VIEW")
        tl.setStyleSheet("color: rgba(0,229,255,0.90); font-weight: 900; letter-spacing: 1.2px;")
        center_l.addWidget(tl)

        if HAS_WEBENGINE:
            self.web = QWebEngineView()  # type: ignore
            self.web.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            center_l.addWidget(self.web, 1)
        else:
            self.web = None
            ph = QLabel("Embedded browser not installed.\nInstall: pip install PyQt6-WebEngine\n(or enable external browser in Settings)")
            ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ph.setStyleSheet("color: rgba(234,242,255,0.65);")
            ph.setMinimumHeight(380)
            center_l.addWidget(ph, 1)

        grid.addWidget(center_wrap, 1, 1, 2, 1)

        right_wrap = card_frame()
        right = QVBoxLayout(right_wrap)
        right.setContentsMargins(10, 10, 10, 10)
        right.setSpacing(10)

        lbl1 = QLabel("OPERATOR CONSOLE")
        lbl1.setStyleSheet("color: rgba(0,229,255,0.90); font-weight: 900; letter-spacing: 1.2px;")
        right.addWidget(lbl1)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(2000)
        self.console.setMinimumHeight(220)
        right.addWidget(self.console, 2)

        lbl2 = QLabel("PROCESS FEED")
        lbl2.setStyleSheet("color: rgba(0,229,255,0.90); font-weight: 900; letter-spacing: 1.2px;")
        right.addWidget(lbl2)
        self.feed = QPlainTextEdit()
        self.feed.setReadOnly(True)
        self.feed.setMaximumBlockCount(2000)
        self.feed.setMinimumHeight(150)
        right.addWidget(self.feed, 1)

        self.telemetry = GlobeTelemetry()
        right.addWidget(self.telemetry, 0)

        grid.addWidget(right_wrap, 1, 2, 2, 1)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 2)
        grid.setColumnStretch(2, 1)

        grid.setRowStretch(1, 1)
        grid.setRowStretch(2, 1)

        self.btn_exec.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_pdf.clicked.connect(self.export_pdf_clicked)
        self.btn_json.clicked.connect(self.export_json_clicked)

        self.btn_pdf.setEnabled(False)
        self.btn_json.setEnabled(False)

        return w

    # ───────────── TAB 2: Findings ─────────────
    def _tab_findings(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)

        self.tbl_findings = QTableWidget(0, 7)
        self.tbl_findings.setHorizontalHeaderLabels([
            "SEV", "CATEGORY", "CONF", "HTTP", "OUTCOME", "FINDING", "REMEDIATION"
        ])
        self.tbl_findings.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_findings.setAlternatingRowColors(True)
        l.addWidget(self.tbl_findings)
        return w

    # ───────────── TAB: Intel ─────────────
    def _tab_intel(self) -> QWidget:
        w = QWidget()
        grid = QGridLayout(w)
        grid.setContentsMargins(10, 10, 10, 10)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)

        gb_reco = QGroupBox("AI RECOMMENDATIONS")
        v1 = QVBoxLayout(gb_reco)
        self.txt_reco = QPlainTextEdit()
        self.txt_reco.setReadOnly(True)
        v1.addWidget(self.txt_reco)

        gb_comp = QGroupBox("COMPLIANCE MAPPING (OWASP / PCI / ISO)")
        v2 = QVBoxLayout(gb_comp)
        self.txt_comp = QPlainTextEdit()
        self.txt_comp.setReadOnly(True)
        v2.addWidget(self.txt_comp)

        gb_disc = QGroupBox("DISCOVERY (SUBDOMAINS / WAF / CLOUD / WS / GRAPHQL)")
        v3 = QVBoxLayout(gb_disc)
        self.txt_disc = QPlainTextEdit()
        self.txt_disc.setReadOnly(True)
        v3.addWidget(self.txt_disc)

        gb_cve = QGroupBox("CVE INTELLIGENCE (BEST-EFFORT)")
        v4 = QVBoxLayout(gb_cve)
        self.txt_cve = QPlainTextEdit()
        self.txt_cve.setReadOnly(True)
        v4.addWidget(self.txt_cve)

        gb_hist = QGroupBox("HISTORY (LOCAL)")
        v5 = QVBoxLayout(gb_hist)
        self.txt_hist = QPlainTextEdit()
        self.txt_hist.setReadOnly(True)
        v5.addWidget(self.txt_hist)

        grid.addWidget(gb_reco, 0, 0, 1, 1)
        grid.addWidget(gb_comp, 0, 1, 1, 1)
        grid.addWidget(gb_disc, 1, 0, 1, 1)
        grid.addWidget(gb_cve, 1, 1, 1, 1)
        grid.addWidget(gb_hist, 2, 0, 1, 2)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        return w

    # ───────────── TAB 3: HTTP Matrix ─────────────
    def _tab_http_matrix(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)

        self.tbl_http = QTableWidget(0, 4)
        self.tbl_http.setHorizontalHeaderLabels(["METHOD", "ALLOWED", "STATUS", "NOTES"])
        self.tbl_http.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_http.setAlternatingRowColors(True)
        l.addWidget(self.tbl_http)
        return w

    # ───────────── TAB 4: Broken Links ─────────────
    def _tab_broken_links(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)

        self.tbl_links = QTableWidget(0, 3)
        self.tbl_links.setHorizontalHeaderLabels(["STATUS", "URL", "NOTE"])
        self.tbl_links.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_links.setAlternatingRowColors(True)
        l.addWidget(self.tbl_links)
        return w

    # ───────────── TAB 5: Network ─────────────
    def _tab_network(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)

        self.tbl_net = QTableWidget(0, 2)
        self.tbl_net.setHorizontalHeaderLabels(["METRIC", "VALUE"])
        self.tbl_net.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        l.addWidget(self.tbl_net)
        return w

    # ───────────── TAB 6: Settings ─────────────
    def _tab_settings(self) -> QWidget:
        w = QWidget()
        grid = QGridLayout(w)
        grid.setContentsMargins(10, 10, 10, 10)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)

        gb_mod = QGroupBox("MODULE SELECTION")
        vm = QVBoxLayout(gb_mod)

        self.cb_headers = QCheckBox("Headers / Disclosure")
        self.cb_tls = QCheckBox("TLS / HTTPS")
        self.cb_cookies = QCheckBox("Cookie Flags")
        self.cb_cors = QCheckBox("CORS Checks")
        self.cb_click = QCheckBox("Clickjacking Checks")
        self.cb_expo = QCheckBox("Exposure Probes (signature-gated)")
        self.cb_robots = QCheckBox("robots.txt + security.txt")
        self.cb_links = QCheckBox("Broken Link Checker (same-host)")
        self.cb_net = QCheckBox("Network Diagnostics (DNS + 80/443 RTT)")
        self.cb_httpm = QCheckBox("HTTP Matrix (OPTIONS + safe probes)")

        # NEW
        self.cb_advnet = QCheckBox("Advanced Network Diagnostics")
        self.cb_ai = QCheckBox("AI-Powered Analysis & Recommendations")
        self.cb_cve = QCheckBox("Real-time CVE Intelligence")
        self.cb_js = QCheckBox("JavaScript Secret Scanner (masked)")
        self.cb_sub = QCheckBox("Subdomain Enumeration (passive CT logs)")
        self.cb_waf = QCheckBox("WAF Detection (fingerprint + hardening)")
        self.cb_cloud = QCheckBox("Cloud Storage Scanner (AWS/Azure/GCP refs)")
        self.cb_gql = QCheckBox("GraphQL API Discovery & Testing (safe)")
        self.cb_ws = QCheckBox("WebSocket Detection")
        self.cb_rl = QCheckBox("Rate Limiting Tests (Authorized Mode)")
        self.cb_hist = QCheckBox("Historical Trending & Comparison (local)")
        self.cb_comp = QCheckBox("OWASP/PCI/ISO Control Mapping")

        for cb in [
            self.cb_headers, self.cb_tls, self.cb_cookies, self.cb_cors, self.cb_click,
            self.cb_expo, self.cb_robots, self.cb_links, self.cb_net, self.cb_httpm,
            self.cb_advnet, self.cb_ai, self.cb_cve, self.cb_js, self.cb_sub, self.cb_waf,
            self.cb_cloud, self.cb_gql, self.cb_ws, self.cb_rl, self.cb_hist, self.cb_comp
        ]:
            cb.setChecked(True)
            vm.addWidget(cb)

        # safer defaults
        self.cb_rl.setChecked(False)

        vm.addStretch(1)

        gb_auth = QGroupBox("AUTHENTICATION")
        fa = QFormLayout(gb_auth)
        self.cb_auth_enable = QCheckBox("Enable Authentication")
        self.auth_type = QComboBox()
        self.auth_type.addItems(["None", "Basic", "Bearer", "Header"])
        self.auth_user = QLineEdit()
        self.auth_pass = QLineEdit()
        self.auth_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_token = QLineEdit()
        self.auth_hname = QLineEdit()
        self.auth_hval = QLineEdit()

        fa.addRow(self.cb_auth_enable)
        fa.addRow("Type", self.auth_type)
        fa.addRow("Username", self.auth_user)
        fa.addRow("Password", self.auth_pass)
        fa.addRow("Bearer Token", self.auth_token)
        fa.addRow("Header Name", self.auth_hname)
        fa.addRow("Header Value", self.auth_hval)

        gb_beh = QGroupBox("BEHAVIOR")
        vb = QVBoxLayout(gb_beh)
        self.cb_follow = QCheckBox("Follow redirects")
        self.cb_verify = QCheckBox("Verify SSL")
        self.cb_authorized = QCheckBox("Authorized Mode (required for Aggressive profile)")
        self.cb_danger = QCheckBox("Allow dangerous method probe (TRACE) [OFF recommended]")
        self.cb_external = QCheckBox("Open external browser on Execute (if no embedded view)")

        self.cb_follow.setChecked(True)
        self.cb_verify.setChecked(True)
        self.cb_authorized.setChecked(False)
        self.cb_danger.setChecked(False)
        self.cb_external.setChecked(False)

        vb.addWidget(self.cb_follow)
        vb.addWidget(self.cb_verify)
        vb.addWidget(self.cb_authorized)
        vb.addWidget(self.cb_danger)
        vb.addWidget(self.cb_external)
        vb.addStretch(1)

        btn_apply = QPushButton("Apply Settings")
        btn_apply.clicked.connect(self.apply_settings)

        grid.addWidget(gb_mod, 0, 0, 2, 1)
        grid.addWidget(gb_auth, 0, 1, 1, 1)
        grid.addWidget(gb_beh, 1, 1, 1, 1)
        grid.addWidget(btn_apply, 2, 1, 1, 1, alignment=Qt.AlignmentFlag.AlignRight)

        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 3)
        grid.setRowStretch(0, 1)
        grid.setRowStretch(1, 1)
        return w

    def apply_settings(self):
        self.cfg.mod_headers = self.cb_headers.isChecked()
        self.cfg.mod_tls = self.cb_tls.isChecked()
        self.cfg.mod_cookies = self.cb_cookies.isChecked()
        self.cfg.mod_cors = self.cb_cors.isChecked()
        self.cfg.mod_clickjacking = self.cb_click.isChecked()
        self.cfg.mod_exposures = self.cb_expo.isChecked()
        self.cfg.mod_robots_securitytxt = self.cb_robots.isChecked()
        self.cfg.mod_broken_links = self.cb_links.isChecked()
        self.cfg.mod_network = self.cb_net.isChecked()
        self.cfg.mod_http_matrix = self.cb_httpm.isChecked()

        self.cfg.mod_adv_network = self.cb_advnet.isChecked()
        self.cfg.mod_ai_reco = self.cb_ai.isChecked()
        self.cfg.mod_cve_intel = self.cb_cve.isChecked()
        self.cfg.mod_js_secrets = self.cb_js.isChecked()
        self.cfg.mod_subdomains = self.cb_sub.isChecked()
        self.cfg.mod_waf_detect = self.cb_waf.isChecked()
        self.cfg.mod_cloud_storage = self.cb_cloud.isChecked()
        self.cfg.mod_graphql = self.cb_gql.isChecked()
        self.cfg.mod_websocket = self.cb_ws.isChecked()
        self.cfg.mod_rate_limit = self.cb_rl.isChecked()
        self.cfg.mod_history = self.cb_hist.isChecked()
        self.cfg.mod_compliance = self.cb_comp.isChecked()

        self.cfg.follow_redirects = self.cb_follow.isChecked()
        self.cfg.verify_ssl = self.cb_verify.isChecked()
        self.cfg.authorized_mode = self.cb_authorized.isChecked()
        self.cfg.allow_dangerous_methods = self.cb_danger.isChecked()
        self.cfg.open_external_browser = self.cb_external.isChecked()

        self.auth.enabled = self.cb_auth_enable.isChecked()
        self.auth.auth_type = self.auth_type.currentText()
        self.auth.username = self.auth_user.text().strip()
        self.auth.password = self.auth_pass.text()
        self.auth.token = self.auth_token.text().strip()
        self.auth.header_name = self.auth_hname.text().strip()
        self.auth.header_value = self.auth_hval.text().strip()

        QMessageBox.information(self, "Settings Applied", "Settings updated successfully.")

    # ───────────── Scan controls ─────────────
    def start_scan(self):
        url = self.in_url.text().strip()
        if not url or url == "https://":
            QMessageBox.warning(self, "Input Required", "Please enter a valid target URL.")
            return

        self.cfg.http_profile = self.in_profile.currentText()

        if self.cfg.http_profile == "Aggressive" and not self.cfg.authorized_mode:
            QMessageBox.warning(
                self,
                "Authorized Mode Required",
                "Aggressive profile requires Authorized Mode.\nEnable it in Settings → Behavior."
            )
            return

        self.current = None
        self._cancel_evt.clear()
        self.console.clear()
        self.feed.clear()
        self.prog.setValue(0)
        self.tbl_findings.setRowCount(0)
        self.tbl_http.setRowCount(0)
        self.tbl_links.setRowCount(0)
        self.tbl_net.setRowCount(0)
        self.txt_reco.clear()
        self.txt_comp.clear()
        self.txt_disc.clear()
        self.txt_cve.clear()
        self.txt_hist.clear()

        self.card_status.set_value("SCANNING", "Audit in progress...", QColor("#FACC15"))
        self.telemetry.set_active(True)

        self.btn_exec.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_pdf.setEnabled(False)
        self.btn_json.setEnabled(False)

        nurl = normalize_url(url)
        if HAS_WEBENGINE and self.web is not None:
            self.web.load(QUrl(nurl))  # type: ignore
        else:
            if self.cfg.open_external_browser:
                import webbrowser
                webbrowser.open(nurl)

        self._thread = QThread()
        self._worker = ScanWorker(nurl, self.cfg, self.auth, self._cancel_evt)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self._on_log)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)

        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def stop_scan(self):
        self._cancel_evt.set()
        self._on_log("[op] Cancel requested...")
        self.card_status.set_value("CANCELLING", "Stopping modules...", QColor("#FB923C"))

    # ───────────── Worker events ─────────────
    def _on_log(self, line: str):
        self.console.appendPlainText(line)
        if line.startswith("[scan]") or line.startswith("[done]") or line.startswith("[warn]") or line.startswith("[ok]"):
            self.feed.appendPlainText(line)

    def _on_progress(self, pct: int, msg: str):
        self.prog.setValue(pct)
        self.status.showMessage(msg)
        if pct < 100:
            self.card_req.set_value("—", f"{msg}")

    def _on_finished(self, res: ScanResult):
        self.current = res
        self.telemetry.set_active(False)

        band, col = risk_band(res.risk_score)
        self.card_risk.set_value(f"{res.risk_score}/100", band, col)
        self.gauge.set_score(res.risk_score)
        self.card_req.set_value(f"{res.requests_ok} / {res.requests_total} OK", "Requests")

        self.card_status.set_value("COMPLETE", "Review findings & export report.", QColor("#4ADE80"))
        self.status.showMessage(f"Complete. Risk {res.risk_score}/100 ({band})")

        self.btn_exec.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_pdf.setEnabled(True)
        self.btn_json.setEnabled(True)

        self._fill_findings(res)
        self._fill_http(res)
        self._fill_links(res)
        self._fill_network(res)
        self._fill_intel(res)

        if res.risk_score >= 70:
            self.tabs.setCurrentIndex(1)

        QMessageBox.information(
            self,
            "Scan Complete",
            f"Target: {res.target}\nRisk: {res.risk_score}/100 ({band})\nFindings: {len(res.findings)}\nDuration: {res.duration_s}s"
        )

    # ───────────── Populate tables ─────────────
    def _fill_findings(self, res: ScanResult):
        self.tbl_findings.setRowCount(0)
        for f in res.findings:
            r = self.tbl_findings.rowCount()
            self.tbl_findings.insertRow(r)

            vals = [f.severity, f.category, f.confidence, f.http_method, f.outcome, f.finding, f.remediation]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(str(v))
                if c == 0:
                    it.setForeground(SEV_COLOR.get(f.severity, QColor("#EAF2FF")))
                    font = it.font()
                    font.setBold(True)
                    it.setFont(font)
                self.tbl_findings.setItem(r, c, it)

    def _fill_http(self, res: ScanResult):
        self.tbl_http.setRowCount(0)
        for x in res.http_matrix:
            r = self.tbl_http.rowCount()
            self.tbl_http.insertRow(r)
            self.tbl_http.setItem(r, 0, QTableWidgetItem(x.method))
            self.tbl_http.setItem(r, 1, QTableWidgetItem(x.allowed))
            self.tbl_http.setItem(r, 2, QTableWidgetItem(x.status))
            self.tbl_http.setItem(r, 3, QTableWidgetItem(x.notes))

    def _fill_links(self, res: ScanResult):
        self.tbl_links.setRowCount(0)
        for x in res.broken_links:
            r = self.tbl_links.rowCount()
            self.tbl_links.insertRow(r)
            self.tbl_links.setItem(r, 0, QTableWidgetItem(x.status))
            self.tbl_links.setItem(r, 1, QTableWidgetItem(x.url))
            self.tbl_links.setItem(r, 2, QTableWidgetItem(x.note))

    def _fill_network(self, res: ScanResult):
        self.tbl_net.setRowCount(0)
        n = res.network

        rows = [
            ("DNS IPs", ", ".join(n.dns_ips) if n.dns_ips else "—"),
            ("IPv6 Present", "Yes" if n.ipv6_present else "No"),
            ("RTT 80 (ms)", str(n.rtt_80_ms) if n.rtt_80_ms is not None else "—"),
            ("RTT 443 (ms)", str(n.rtt_443_ms) if n.rtt_443_ms is not None else "—"),
            ("HTTP → HTTPS Redirect", ("Yes" if n.http_redirect_to_https else "No") if n.http_redirect_to_https is not None else "—"),
            ("TLS Version", n.tls_version or "—"),
            ("ALPN", n.tls_alpn or "—"),
            ("Cipher", n.tls_cipher or "—"),
            ("Cert Days Left", str(n.cert_days_left) if n.cert_days_left is not None else "—"),
            ("Cert Subject", n.cert_subject or "—"),
            ("Cert Issuer", n.cert_issuer or "—"),
        ]

        for k, v in rows:
            r = self.tbl_net.rowCount()
            self.tbl_net.insertRow(r)
            self.tbl_net.setItem(r, 0, QTableWidgetItem(k))
            self.tbl_net.setItem(r, 1, QTableWidgetItem(v))

    def _fill_intel(self, res: ScanResult):
        # Recommendations
        if res.recommendations:
            self.txt_reco.setPlainText("\n".join([f"{i+1}. {x}" for i, x in enumerate(res.recommendations)]))
        else:
            self.txt_reco.setPlainText("—")

        # Compliance
        if res.compliance:
            out = []
            for k, lines in res.compliance.items():
                out.append(k)
                out.append("-" * len(k))
                for ln in (lines or [])[:50]:
                    out.append(f"• {ln}")
                out.append("")
            self.txt_comp.setPlainText("\n".join(out).strip())
        else:
            self.txt_comp.setPlainText("—")

        # Discovery
        disc = res.discovery or {}
        outd = []
        outd.append(f"WAF/CDN: {', '.join(disc.get('waf', [])) if disc.get('waf') else '—'}")
        outd.append(f"Subdomains: {len(disc.get('subdomains', []) or [])}")
        outd.append(f"GraphQL: {len(disc.get('graphql', []) or [])}")
        outd.append(f"WebSockets: {len(disc.get('websockets', []) or [])}")
        cloud = disc.get("cloud_refs") or {}
        outd.append(f"Cloud refs: AWS S3={len(cloud.get('aws_s3', []))} | Azure Blob={len(cloud.get('azure_blob', []))} | GCP={len(cloud.get('gcp_storage', []))}")
        secrets = disc.get("js_secrets") or []
        outd.append(f"JS Secrets indicators: {len(secrets)} (masked)")
        if secrets:
            outd.append("")
            outd.append("Sample indicators:")
            for s in secrets[:8]:
                outd.append(f"- {s.get('type')} | {s.get('value')} | {s.get('file')}")
        subs = disc.get("subdomains") or []
        if subs:
            outd.append("")
            outd.append("Subdomains (top):")
            for s in subs[:25]:
                outd.append(f"- {s}")
        self.txt_disc.setPlainText("\n".join(outd))

        # CVE
        if res.cve_intel:
            outc = []
            for block in res.cve_intel[:10]:
                outc.append(f"Keyword: {block.get('query')}")
                for item in (block.get("top") or [])[:10]:
                    outc.append(f"- {item.get('id')} | CVSS={item.get('cvss')} | {item.get('summary')}")
                outc.append("")
            self.txt_cve.setPlainText("\n".join(outc).strip())
        else:
            self.txt_cve.setPlainText("—")

        # History
        if res.history:
            h = res.history
            out = []
            out.append(f"History file: {h.get('history_path', '—')}")
            if h.get("delta_risk") is not None:
                out.append(f"Delta risk vs previous: {h.get('delta_risk'):+d}")
            prev = h.get("previous")
            if prev:
                out.append("")
                out.append("Previous run summary:")
                out.append(json.dumps(prev, indent=2, ensure_ascii=False))
            self.txt_hist.setPlainText("\n".join(out))
        else:
            self.txt_hist.setPlainText("—")

    # ───────────── Export ─────────────
    def export_json_clicked(self):
        if not self.current:
            QMessageBox.warning(self, "No Data", "Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "nightfall_tsukuyomi_report.json", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(asdict(self.current), f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Exported", f"Saved:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_pdf_clicked(self):
        if not self.current:
            QMessageBox.warning(self, "No Data", "Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save PDF", "nightfall_tsukuyomi_report.pdf", "PDF (*.pdf)")
        if not path:
            return
        try:
            export_pdf(path, self.current)
            QMessageBox.information(self, "Exported", f"Saved:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "PDF Export Error", str(e))


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(THEME)

    win = NightfallTsukuyomiApp()
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
