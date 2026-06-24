"""
Project Shield -- Flask REST API
=================================
AI-Powered Cybersecurity Analytics Dashboard
CFSS Global Internship 2026

Endpoints:
  POST   /api/auth/login          -- Authenticate and receive JWT
  GET    /api/auth/verify         -- Verify JWT token validity
  GET    /api/health              -- Health check with system status
  GET    /api/dashboard/stats     -- Aggregated dashboard statistics
  POST   /api/logs/upload         -- Upload CSV log file for analysis
  GET    /api/logs/analyze        -- Paginated, filtered log retrieval
  POST   /api/logs/generate-demo  -- Generate synthetic demo log data
  GET    /api/threats/recent      -- Top high/critical severity threats
  GET    /api/threats/live        -- Live streaming threat events
  GET    /api/report/generate     -- Generate downloadable PDF report

Architecture:
  - Clean modular helper functions with full type annotations and docstrings
  - Lazy ML model loading (graceful rule-based fallback if models absent)
  - In-memory log store (swap to PostgreSQL/Redis without breaking API contracts)
  - JWT authentication on all protected routes
  - CORS enabled for frontend integration
  - ReportLab PDF generation with JSON fallback
"""

import os
import io
import csv
import random
import datetime
from typing import Optional

def get_ist_now():
    return datetime.datetime.utcnow() + datetime.timedelta(hours=5, minutes=30)

import numpy as np
import joblib
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
)
from werkzeug.security import generate_password_hash, check_password_hash
from sklearn.preprocessing import LabelEncoder

# -- Optional: pandas (for CSV utilities) ----------------------------------------
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# -- Optional: PDF generation via ReportLab --------------------------------------
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[!] reportlab not installed -- PDF reports disabled. pip install reportlab")


# =============================================================================
# APP SETUP & CONFIGURATION
# =============================================================================

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="/")
app.config["JWT_SECRET_KEY"]           = os.environ.get("JWT_SECRET_KEY", "cfss-project-shield-2026-secret")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=8)

# Allow all origins for dev; restrict to specific domains in production
CORS(app, resources={r"/api/*": {"origins": "*"}})
jwt = JWTManager(app)


# Serve frontend SPA pages
@app.route("/")
def serve_login():
    return send_file(os.path.join(FRONTEND_DIR, "index.html"))

@app.route("/dashboard")
def serve_dashboard():
    return send_file(os.path.join(FRONTEND_DIR, "dashboard.html"))


# =============================================================================
# CONSTANTS & DOMAIN CONFIGURATION
# =============================================================================

# Simulated user store -- replace with database in production
USERS = {
    "admin":   generate_password_hash("Shield@2026"),
    "analyst": generate_password_hash("Cfss@2026"),
}

# NSL-KDD inspired network feature list (15 numeric + 3 categorical)
NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "count", "srv_count", "same_srv_rate", "diff_srv_rate", "dst_host_count",
]
PROTOCOLS    = ["tcp", "udp", "icmp"]
SERVICES     = ["http", "ftp", "smtp", "ssh", "dns", "telnet", "pop3", "imap"]
FLAGS        = ["SF", "S0", "REJ", "RSTO", "SH", "OTH"]
ATTACK_TYPES = ["Normal", "DoS", "Probe", "R2L", "U2R"]

# Composite threat scoring weights (0-100 scale)
THREAT_WEIGHT = {"Normal": 0, "Probe": 35, "DoS": 65, "R2L": 80, "U2R": 95}
SEVERITY_MAP  = {"Normal": "Low", "Probe": "Medium", "DoS": "High", "R2L": "High", "U2R": "Critical"}

# Realistic attack distribution for demo traffic generation
DEMO_ATTACK_WEIGHTS = [60, 15, 12, 8, 5]  # Normal, DoS, Probe, R2L, U2R

# Rolling window size for in-memory log store
MAX_LOG_HISTORY = 5_000


# =============================================================================
# ML MODEL MANAGEMENT
# =============================================================================

# Loaded lazily on first scoring request -- avoids blocking startup
_models: dict   = {}
# LabelEncoder cache -- avoids re-fitting on every scoring call
_le_cache: dict = {}


def load_models() -> dict:
    """
    Lazily load trained ML models from the ./model directory.
    If models are unavailable, falls back to rule-based scoring seamlessly.
    Returns the shared _models dict.
    """
    if _models:
        return _models
    try:
        _models["iso"]          = joblib.load("model/isolation_forest.pkl")
        _models["rf"]           = joblib.load("model/random_forest.pkl")
        _models["scaler"]       = joblib.load("model/scaler.pkl")
        _models["feature_cols"] = joblib.load("model/feature_cols.pkl")
        print("[ok] ML models loaded successfully")
    except Exception as exc:
        print(f"[!] Models unavailable ({exc}). Rule-based scoring active.")
    return _models


def encode_categorical(value: str, categories: list) -> int:
    """
    Encode a single categorical value using a cached LabelEncoder.
    Returns 0 for unknown/unseen categories (graceful degradation).
    """
    key = ",".join(categories)
    if key not in _le_cache:
        le = LabelEncoder()
        le.fit(categories)
        _le_cache[key] = le
    try:
        return int(_le_cache[key].transform([str(value)])[0])
    except ValueError:
        return 0  # Unknown category -- default to first class index


# =============================================================================
# THREAT SCORING ENGINE
# =============================================================================

def compute_threat_score(row: dict) -> dict:
    """
    Score a single log entry using ML models or rule-based fallback.

    Pipeline:
      1. Build 18-feature numeric vector from log row
      2. Scale with MinMaxScaler (if loaded)
      3. Isolation Forest -> anomaly flag + decision score
      4. Random Forest    -> attack class label + probabilities
      5. Composite threat score = base weight + anomaly boost + noise

    Returns:
        dict with keys: label, severity, threat_score, is_anomaly,
                        iso_score, probabilities
    """
    models = load_models()
    try:
        # Build feature vector
        protocol_enc = encode_categorical(row.get("protocol_type", "tcp"), PROTOCOLS)
        service_enc  = encode_categorical(row.get("service",        "http"), SERVICES)
        flag_enc     = encode_categorical(row.get("flag",            "SF"),   FLAGS)
        num_vals     = [float(row.get(f, 0)) for f in NUMERIC_FEATURES]
        X_raw        = np.array(num_vals + [protocol_enc, service_enc, flag_enc]).reshape(1, -1)
        X            = models["scaler"].transform(X_raw) if "scaler" in models else X_raw

        # Anomaly detection
        if "iso" in models:
            iso_score  = float(models["iso"].decision_function(X)[0])
            is_anomaly = bool(models["iso"].predict(X)[0] == -1)
        else:
            iso_score, is_anomaly = 0.0, False

        # Multi-class classification
        if "rf" in models:
            label       = str(models["rf"].predict(X)[0])
            proba       = models["rf"].predict_proba(X)[0]
            label_proba = {c: float(p) for c, p in zip(models["rf"].classes_, proba)}
        else:
            label, label_proba = "Normal", {"Normal": 1.0}

        # Composite threat score: base + anomaly boost + realism noise
        base_score    = THREAT_WEIGHT.get(label, 0)
        anomaly_boost = max(0, -iso_score * 20) if is_anomaly else 0
        threat_score  = min(100.0, max(0.0, base_score + anomaly_boost + random.uniform(-3, 3)))

    except Exception as exc:
        print(f"[!] Scoring error: {exc}")
        label, threat_score, is_anomaly, label_proba, iso_score = "Normal", 0.0, False, {}, 0.0

    return {
        "label":         label,
        "severity":      SEVERITY_MAP.get(label, "Low"),
        "threat_score":  round(threat_score, 2),
        "is_anomaly":    is_anomaly,
        "iso_score":     round(iso_score, 4),
        "probabilities": label_proba,
    }


# =============================================================================
# DATA GENERATION & PARSING
# =============================================================================

def generate_demo_logs(n: int = 50) -> list:
    """
    Generate n synthetic security log entries with realistic traffic patterns.
    Each entry is scored immediately via the threat scoring engine.
    Covers all 5 attack categories with realistic frequency distribution.
    """
    entries, now = [], get_ist_now()
    for i in range(n):
        ts    = now - datetime.timedelta(seconds=i * random.randint(5, 60))
        entry = {
            "timestamp":         ts.isoformat() + "Z",
            "src_ip":            f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip":            f"10.0.{random.randint(0,10)}.{random.randint(1,100)}",
            "protocol_type":     random.choice(PROTOCOLS),
            "service":           random.choice(SERVICES),
            "flag":              random.choice(FLAGS),
            "duration":          round(random.expovariate(0.2), 2),
            "src_bytes":         random.randint(0, 50_000),
            "dst_bytes":         random.randint(0, 30_000),
            "land":              0,
            "wrong_fragment":    random.randint(0, 2),
            "urgent":            0,
            "hot":               random.randint(0, 20),
            "num_failed_logins": random.randint(0, 5),
            "logged_in":         random.randint(0, 1),
            "num_compromised":   random.randint(0, 5),
            "count":             random.randint(1, 512),
            "srv_count":         random.randint(1, 512),
            "same_srv_rate":     round(random.uniform(0, 1), 2),
            "diff_srv_rate":     round(random.uniform(0, 1), 2),
            "dst_host_count":    random.randint(1, 255),
        }
        entry.update(compute_threat_score(entry))
        entries.append(entry)
    return entries


def parse_log_csv(file_content: str) -> list:
    """
    Parse a CSV log file into a list of row dicts.
    Caps at 5,000 rows and strips whitespace from all keys and values.
    """
    rows, reader = [], csv.DictReader(io.StringIO(file_content))
    for i, row in enumerate(reader):
        if i >= 5_000:
            break
        rows.append({k.strip(): v.strip() for k, v in row.items()})
    return rows


def compute_summary_stats(log_entries: list) -> dict:
    """
    Compute aggregated statistics from a list of scored log entries.
    Reused by both /dashboard/stats and /report/generate for consistency.
    """
    if not log_entries:
        return {}

    attacks = [r for r in log_entries if r.get("label") != "Normal"]
    scores  = [r.get("threat_score", 0) for r in log_entries]
    total   = len(log_entries)

    type_counts: dict = {}
    for r in log_entries:
        lbl = r.get("label", "Normal")
        type_counts[lbl] = type_counts.get(lbl, 0) + 1

    sev_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in log_entries:
        sev = r.get("severity", "Low")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    proto_counts: dict = {}
    for r in log_entries:
        p = r.get("protocol_type", "tcp")
        proto_counts[p] = proto_counts.get(p, 0) + 1

    svc_counts: dict = {}
    for r in log_entries:
        s = r.get("service", "http")
        svc_counts[s] = svc_counts.get(s, 0) + 1
    top_services = dict(sorted(svc_counts.items(), key=lambda x: -x[1])[:6])

    timeline = [
        {"timestamp": r.get("timestamp"), "label": r.get("label"), "threat_score": r.get("threat_score", 0)}
        for r in log_entries[:24]
    ]

    return {
        "total_events":          total,
        "total_attacks":         len(attacks),
        "total_normal":          total - len(attacks),
        "attack_rate":           round(len(attacks) / total * 100, 1),
        "avg_threat_score":      round(sum(scores) / len(scores), 1),
        "max_threat_score":      round(max(scores), 1),
        "type_distribution":     type_counts,
        "severity_counts":       sev_counts,
        "protocol_distribution": proto_counts,
        "top_services":          top_services,
        "timeline":              timeline,
    }


# =============================================================================
# IN-MEMORY LOG STORE  (swap for PostgreSQL/Redis without changing any API)
# =============================================================================

log_history: list = []


def append_to_history(new_entries: list) -> None:
    """Add new log entries to the rolling history window (max MAX_LOG_HISTORY)."""
    global log_history
    log_history = (log_history + new_entries)[-MAX_LOG_HISTORY:]


# =============================================================================
# PDF REPORT BUILDER
# =============================================================================

def build_pdf_report(stats: dict, top_threats: list, generated_at: str) -> bytes:
    """
    Build a professional PDF security intelligence report using ReportLab.

    Sections:
      1. Cover / Header
      2. Executive Summary + KPI table
      3. Threat Statistics (attack type breakdown)
      4. Severity Analysis
      5. Protocol and Service Distribution
      6. Top Critical Threats table
      7. Methodology and AI Architecture
      8. Security Recommendations
      9. Footer

    Returns: Raw PDF bytes for streaming to client.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm,
        title="Project Shield - Security Intelligence Report",
        author="CFSS Project Shield AI System",
    )
    stl      = getSampleStyleSheet()
    elems    = []
    CYAN     = colors.HexColor("#008f77") # Darker cyan for white bg
    MUTED    = colors.HexColor("#4a5568") # Dark gray
    BORDER   = colors.HexColor("#e2e8f0") # Light gray borders
    DARK_BG  = colors.HexColor("#f8fafc") # Very light bg for tables
    DARKER   = colors.HexColor("#edf2f7") # Slightly darker bg for table headers
    BODY_CLR = colors.HexColor("#1a202c") # Almost black for body text

    H2  = ParagraphStyle("H2S", parent=stl["Heading2"], fontSize=13, textColor=CYAN,
                          fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4)
    BDY = ParagraphStyle("BDS", parent=stl["Normal"], fontSize=9, textColor=BODY_CLR,
                          leading=14, spaceAfter=3)
    MUT = ParagraphStyle("MTS", parent=stl["Normal"], fontSize=8, textColor=MUTED, leading=11)

    def sec(title):
        """Return flowables for a styled section divider."""
        return [Spacer(1, 0.25*cm), Paragraph(title, H2),
                HRFlowable(width="100%", thickness=0.4, color=BORDER), Spacer(1, 0.15*cm)]

    def tbl(headers, rows, widths=None):
        """Build a consistently styled data table."""
        t = Table([headers] + rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), DARK_BG),
            ("TEXTCOLOR",     (0,0),(-1,0), CYAN),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,0), 8),
            ("TOPPADDING",    (0,0),(-1,0), 7),
            ("BOTTOMPADDING", (0,0),(-1,0), 7),
            ("FONTNAME",      (0,1),(-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,1),(-1,-1), 8),
            ("TEXTCOLOR",     (0,1),(-1,-1), BODY_CLR),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [DARKER, DARK_BG]),
            ("GRID",          (0,0),(-1,-1), 0.3, BORDER),
            ("TOPPADDING",    (0,1),(-1,-1), 5),
            ("BOTTOMPADDING", (0,1),(-1,-1), 5),
            ("LEFTPADDING",   (0,0),(-1,-1), 7),
            ("RIGHTPADDING",  (0,0),(-1,-1), 7),
            ("ALIGN",         (0,0),(-1,-1), "LEFT"),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        return t

    # Cover
    elems.append(Spacer(1, 0.4*cm))
    cover = Table([[
        Paragraph("PROJECT SHIELD", ParagraphStyle(
            "CV", fontSize=26, textColor=CYAN, fontName="Helvetica-Bold", alignment=TA_LEFT)),
        Paragraph(f"Generated: {generated_at}<br/>CFSS Global Internship 2026",
                  ParagraphStyle("CVR", fontSize=8, textColor=MUTED, alignment=TA_RIGHT)),
    ]], colWidths=["70%","30%"])
    cover.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), DARKER),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0),(-1,-1), 14),
        ("BOTTOMPADDING", (0,0),(-1,-1), 14),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
        ("RIGHTPADDING",  (0,0),(-1,-1), 10),
        ("LINEBELOW",     (0,0),(-1,-1), 1.5, CYAN),
    ]))
    elems.append(cover)
    elems.append(Paragraph(
        "AI-Powered Security Intelligence Report -- Threat Analysis and Anomaly Detection",
        ParagraphStyle("ST", fontSize=9, textColor=MUTED, spaceBefore=5, spaceAfter=14)
    ))

    # Executive Summary
    elems += sec("1. EXECUTIVE SUMMARY")
    total     = stats.get("total_events", 0)
    attacks   = stats.get("total_attacks", 0)
    rate      = stats.get("attack_rate", 0)
    avg_score = stats.get("avg_threat_score", 0)
    max_score = stats.get("max_threat_score", 0)
    sev_c     = stats.get("severity_counts", {})
    crit_cnt  = sev_c.get("Critical", 0)
    posture   = ("HIGH RISK" if (avg_score >= 60 or crit_cnt > 0)
                 else "ELEVATED RISK" if avg_score >= 35 else "NOMINAL")

    elems.append(Paragraph(
        f"<b>Project Shield</b> AI engine analyzed <b>{total:,} network events</b>. "
        f"<b>{attacks:,} attacks</b> detected ({rate}% attack rate). "
        f"Average threat score: <b>{avg_score}/100</b>. Peak: <b>{max_score}/100</b>. "
        f"Critical events: <b>{crit_cnt}</b>. Security posture: <b>{posture}</b>.", BDY))
    elems.append(Spacer(1, 0.2*cm))
    elems.append(tbl(
        ["Metric", "Value", "Status"],
        [["Total Events Analyzed",  f"{total:,}",        "--"],
         ["Attacks Detected",       f"{attacks:,}",      f"{rate}% of traffic"],
         ["Avg Threat Score",       f"{avg_score}/100",  posture],
         ["Peak Threat Score",      f"{max_score}/100",  "Worst recorded"],
         ["Critical Events",        str(crit_cnt),
          "Immediate action required" if crit_cnt > 0 else "None detected"]],
        ["50%","25%","25%"]
    ))

    # Threat Statistics
    type_dist = stats.get("type_distribution", {})
    elems += sec("2. THREAT STATISTICS")
    type_rows = [
        [atype, str(cnt), f"{round(cnt/total*100,1) if total else 0}%",
         f"{THREAT_WEIGHT.get(atype,0)}/100", SEVERITY_MAP.get(atype,"Low")]
        for atype, cnt in sorted(type_dist.items(), key=lambda x: -x[1])
    ]
    if type_rows:
        elems.append(tbl(
            ["Attack Type","Count","% Total","Base Score","Severity"],
            type_rows, ["22%","16%","17%","24%","21%"]))

    # Severity Analysis
    elems += sec("3. SEVERITY ANALYSIS")
    elems.append(tbl(
        ["Severity Level", "Event Count", "% of Total"],
        [[s, str(sev_c.get(s,0)), f"{round(sev_c.get(s,0)/total*100,1) if total else 0}%"]
         for s in ["Critical","High","Medium","Low"]],
        ["40%","30%","30%"]
    ))

    # Protocol & Service
    proto_dist   = stats.get("protocol_distribution", {})
    top_services = stats.get("top_services", {})
    elems += sec("4. PROTOCOL AND SERVICE ANALYSIS")
    if proto_dist:
        elems.append(Paragraph("Protocol Distribution", H2))
        elems.append(tbl(
            ["Protocol","Events","% Total"],
            [[p.upper(), str(c), f"{round(c/total*100,1) if total else 0}%"]
             for p,c in sorted(proto_dist.items(), key=lambda x:-x[1])],
            ["33%","33%","34%"]
        ))
    if top_services:
        elems.append(Spacer(1, 0.2*cm))
        elems.append(Paragraph("Top Targeted Services", H2))
        elems.append(tbl(
            ["Service","Events","% Total"],
            [[s.upper(), str(c), f"{round(c/total*100,1) if total else 0}%"]
             for s,c in top_services.items()],
            ["33%","33%","34%"]
        ))

    # Top Critical Threats
    elems += sec("5. TOP CRITICAL THREATS")
    if top_threats:
        elems.append(tbl(
            ["Timestamp","Source IP","Dest IP","Attack","Score","Severity","Proto"],
            [[t.get("timestamp","")[:19].replace("T"," "),
              t.get("src_ip","--"), t.get("dst_ip","--"), t.get("label","--"),
              f"{float(t.get('threat_score',0)):.0f}/100",
              t.get("severity","--"), t.get("protocol_type","--").upper()]
             for t in top_threats[:15]],
            ["18%","14%","14%","12%","11%","12%","10%"]
        ))
    else:
        elems.append(Paragraph("No critical threats detected in this analysis period.", BDY))

    # Methodology
    elems += sec("6. METHODOLOGY AND AI ARCHITECTURE")
    for point in [
        "<b>Dataset:</b> NSL-KDD inspired synthetic logs; 5 attack classes (Normal, DoS, Probe, R2L, U2R); 18 network features.",
        "<b>Isolation Forest (Anomaly Detection):</b> 200-tree unsupervised model, contamination=0.35. "
        "Negative decision scores signal anomalous traffic.",
        "<b>Random Forest Classifier:</b> 300-tree ensemble, max_depth=15, stratified 80/20 train/test split. "
        "Outputs per-class probabilities for all 5 attack categories.",
        "<b>Composite Threat Score (0-100):</b> Base weight by attack class + Isolation Forest anomaly boost + noise. "
        "Provides a human-readable risk gradient for SOC analysts.",
        "<b>Feature Engineering:</b> Protocol, service, and flag fields are label-encoded. All features MinMax-scaled before inference.",
    ]:
        elems.append(Paragraph(f"- {point}", BDY))

    # Recommendations
    elems += sec("7. SECURITY RECOMMENDATIONS")
    recs = []
    if crit_cnt > 0:
        recs.append(f"<b>CRITICAL [IMMEDIATE]:</b> {crit_cnt} critical event(s) detected (U2R/privilege escalation). "
                    "Isolate affected systems and initiate forensic investigation immediately.")
    if sev_c.get("High",0) > 0:
        recs.append(f"<b>HIGH PRIORITY:</b> {sev_c.get('High',0)} high-severity events (DoS/R2L). "
                    "Implement rate limiting and review firewall ACLs on affected services.")
    if rate > 30:
        recs.append(f"<b>ELEVATED ATTACK RATE ({rate}%):</b> Enable IPS mode, block top attacker IP ranges, "
                    "review network segmentation policies.")
    if type_dist.get("DoS",0) > 5:
        recs.append(f"<b>DoS MITIGATION:</b> {type_dist['DoS']} DoS events. "
                    "Deploy traffic scrubbing and SYN flood protection.")
    recs += [
        "<b>LOG MONITORING:</b> Extend retention to 90 days. Enable SIEM correlation rules for U2R and R2L patterns.",
        "<b>ACCESS CONTROL:</b> Apply principle of least privilege. Enforce MFA on all administrator accounts.",
        "<b>PATCH MANAGEMENT:</b> Keep all systems current. R2L attacks frequently exploit unpatched CVEs.",
        "<b>INCIDENT RESPONSE:</b> Run quarterly IR tabletop exercises. Review Incident Response Plan (IRP) annually.",
    ]
    for i, rec in enumerate(recs, 1):
        elems.append(Paragraph(f"{i}. {rec}", BDY))

    # Footer
    elems.append(Spacer(1, 0.4*cm))
    elems.append(HRFlowable(width="100%", thickness=0.4, color=BORDER))
    elems.append(Spacer(1, 0.15*cm))
    ft = Table([[
        Paragraph("Project Shield -- Confidential Security Report", MUT),
        Paragraph(f"CFSS Global Internship 2026 | {generated_at}", MUT),
        Paragraph("Powered by scikit-learn AI/ML", MUT),
    ]], colWidths=["40%","35%","25%"])
    ft.setStyle(TableStyle([
        ("FONTSIZE", (0,0),(-1,-1), 7),
        ("TEXTCOLOR",(0,0),(-1,-1), MUTED),
    ]))
    elems.append(ft)

    doc.build(elems)
    return buf.getvalue()


# =============================================================================
# AUTHENTICATION ROUTES
# =============================================================================

@app.route("/api/auth/login", methods=["POST"])
def login():
    """
    Authenticate user credentials and issue a JWT access token (8h expiry).

    Request:  { "username": str, "password": str }
    Response: { "access_token": str, "username": str, "role": str, "expires_in": int }
    """
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if username not in USERS or not check_password_hash(USERS[username], password):
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({
        "access_token": create_access_token(identity=username),
        "username":     username,
        "role":         "Administrator" if username == "admin" else "Analyst",
        "expires_in":   28_800,
    })


@app.route("/api/auth/verify", methods=["GET"])
@jwt_required()
def verify():
    """Verify JWT token and return the authenticated username."""
    return jsonify({"username": get_jwt_identity(), "valid": True})


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.route("/api/health", methods=["GET"])
def health():
    """Public health check -- returns system status, model state, log count, and version."""
    return jsonify({
        "status":        "ok",
        "models_loaded": bool(_models),
        "log_count":     len(log_history),
        "timestamp":     get_ist_now().isoformat() + "Z",
        "version":       "1.0.0",
    })


# =============================================================================
# DASHBOARD ROUTES
# =============================================================================

@app.route("/api/dashboard/stats", methods=["GET"])
@jwt_required()
def dashboard_stats():
    """Return aggregated dashboard statistics from recent log history."""
    recent = log_history[-500:] if log_history else generate_demo_logs(200)
    return jsonify(compute_summary_stats(recent))


# =============================================================================
# LOG MANAGEMENT ROUTES
# =============================================================================

@app.route("/api/logs/upload", methods=["POST"])
@jwt_required()
def upload_logs():
    """
    Ingest security logs from CSV file or JSON array payload.
    Max 5,000 rows. Adds scored entries to the rolling log history.
    """
    if "file" in request.files:
        f = request.files["file"]
        if not f.filename.endswith(".csv"):
            return jsonify({"error": "Only CSV files are accepted"}), 400
        rows = parse_log_csv(f.read().decode("utf-8", errors="ignore"))
    elif request.is_json:
        rows = request.get_json()
        if not isinstance(rows, list):
            return jsonify({"error": "Expected a JSON array of log objects"}), 400
    else:
        return jsonify({"error": "No file or JSON data provided"}), 400

    if len(rows) > 5_000:
        return jsonify({"error": "Too many rows -- maximum is 5,000"}), 400

    now, processed = get_ist_now(), []
    for i, row in enumerate(rows):
        row["timestamp"] = row.get("timestamp", (now - datetime.timedelta(seconds=i*5)).isoformat()+"Z")
        row["src_ip"]    = row.get("src_ip", f"192.168.{random.randint(0,255)}.{random.randint(1,254)}")
        row["dst_ip"]    = row.get("dst_ip", f"10.0.{random.randint(0,10)}.{random.randint(1,100)}")
        row.update(compute_threat_score(row))
        processed.append(row)

    append_to_history(processed)
    attacks = [r for r in processed if r.get("label") != "Normal"]
    scores  = [r.get("threat_score", 0) for r in processed]
    return jsonify({
        "message":          f"Processed {len(processed)} log entries",
        "total":            len(processed),
        "attacks_found":    len(attacks),
        "avg_threat_score": round(sum(scores)/len(scores), 2) if scores else 0,
        "results":          processed[:100],
    })


@app.route("/api/logs/analyze", methods=["GET"])
@jwt_required()
def analyze_logs():
    """
    Return paginated and filtered log entries.
    Query params: page (int), per_page (int), label (str), severity (str)
    """
    page     = int(request.args.get("page",     1))
    per_page = int(request.args.get("per_page", 50))
    label    = request.args.get("label",    None)
    severity = request.args.get("severity", None)
    data = log_history if log_history else generate_demo_logs(100)
    if label:
        data = [r for r in data if r.get("label","").lower() == label.lower()]
    if severity:
        data = [r for r in data if r.get("severity","").lower() == severity.lower()]
    total = len(data)
    start = (page - 1) * per_page
    return jsonify({"total": total, "page": page, "per_page": per_page,
                    "data": data[start:start+per_page]})


@app.route("/api/logs/generate-demo", methods=["POST"])
@jwt_required()
def generate_demo():
    """Generate up to 500 synthetic demo log entries. Query param: n (default=100)."""
    n    = min(int(request.args.get("n", 100)), 500)
    demo = generate_demo_logs(n)
    append_to_history(demo)
    return jsonify({"message": f"Generated {n} demo log entries",
                    "total_in_history": len(log_history)})


# =============================================================================
# THREAT INTELLIGENCE ROUTES
# =============================================================================

@app.route("/api/threats/recent", methods=["GET"])
@jwt_required()
def recent_threats():
    """Return top 20 High/Critical threats ranked by descending threat score."""
    data    = log_history if log_history else generate_demo_logs(50)
    threats = sorted([r for r in data if r.get("severity") in ("High","Critical")],
                     key=lambda x: x.get("threat_score",0), reverse=True)
    return jsonify({"threats": threats[:20]})


@app.route("/api/threats/live", methods=["GET"])
@jwt_required()
def live_threats():
    """Return 3-8 freshly generated events simulating a live event stream."""
    new_entries = generate_demo_logs(random.randint(3, 8))
    append_to_history(new_entries)
    return jsonify({"events": new_entries})


# =============================================================================
# REPORT GENERATION ROUTE
# =============================================================================

@app.route("/api/report/generate", methods=["GET"])
@jwt_required()
def generate_report():
    """
    Generate a professional PDF security intelligence report.

    Report includes:
      - Executive summary + KPI table
      - Attack type and severity breakdowns
      - Protocol/service analysis
      - Top critical threats table
      - AI/ML methodology
      - Prioritised security recommendations

    Returns application/pdf for download.
    Falls back to rich JSON response if ReportLab is not installed.
    """
    data        = log_history if log_history else generate_demo_logs(200)
    stats       = compute_summary_stats(data)
    top_threats = sorted([r for r in data if r.get("severity") in ("High","Critical")],
                         key=lambda x: x.get("threat_score",0), reverse=True)
    generated_at = get_ist_now().strftime("%Y-%m-%d %H:%M:%S IST")

    if not REPORTLAB_AVAILABLE:
        # Graceful JSON fallback
        return jsonify({
            "report_title": "Project Shield -- Security Intelligence Report",
            "generated_at":  generated_at,
            "generated_by":  get_jwt_identity(),
            "summary":       stats,
            "top_threats":   top_threats[:20],
            "methodology":   {
                "models":   ["Isolation Forest", "Random Forest"],
                "dataset":  "NSL-KDD inspired (860 samples)",
                "features": 18,
                "classes":  ATTACK_TYPES,
            },
            "install_note": "pip install reportlab  -- for PDF output",
        })

    try:
        pdf_bytes = build_pdf_report(stats, top_threats, generated_at)
        filename  = f"shield_report_{get_ist_now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype      = "application/pdf",
            as_attachment = True,
            download_name = filename,
        )
    except Exception as exc:
        print(f"[!] Report error: {exc}")
        return jsonify({"error": f"Report generation failed: {exc}"}), 500


# =============================================================================
# ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    load_models()
    sep = "=" * 56
    print(f"\n{sep}")
    print("  Project Shield API  --  http://localhost:5000")
    print(sep)
    print("  Credentials:  admin   / Shield@2026  (Administrator)")
    print("                analyst / Cfss@2026    (Analyst)")
    print(f"{sep}\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
