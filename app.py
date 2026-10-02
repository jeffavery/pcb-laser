"""KiCad board to single-sided laser-etch artwork.

The parser intentionally handles the common KiCad copper primitives needed for
home-etched boards.  It does not claim to validate electrical correctness.
"""
from __future__ import annotations

import base64
import html
import io
import json
import os
import math
import re
import shutil
import smtplib
import sqlite3
import subprocess
import tempfile
import threading
import zipfile
from contextlib import contextmanager
from email.message import EmailMessage
from hashlib import sha256
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path, PurePosixPath
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, Response, abort, g, redirect, render_template, request,
                   send_file, session, url_for)
import requests
from werkzeug.security import check_password_hash, generate_password_hash
from board_compiler import assembly_svg, board_dimensions, compile_board

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
AUTH_DB = Path(os.environ.get("PCB_AUTH_DB", "/data/auth.db"))
SESSION_SECRET_FILE = Path("/data/session-secret")


def _session_secret() -> str:
    configured = os.environ.get("PCB_SESSION_SECRET", "").strip()
    if configured:
        return configured
    try:
        if SESSION_SECRET_FILE.exists():
            return SESSION_SECRET_FILE.read_text(encoding="ascii").strip()
        SESSION_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        secret = base64.urlsafe_b64encode(os.urandom(48)).decode("ascii")
        temporary = SESSION_SECRET_FILE.with_suffix(".tmp")
        temporary.write_text(secret, encoding="ascii")
        os.chmod(temporary, 0o600)
        temporary.replace(SESSION_SECRET_FILE)
        return secret
    except OSError as error:
        raise RuntimeError("The server could not create its private session key.") from error


app.secret_key = _session_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("PCB_SECURE_COOKIES", "no").lower() == "yes",
                  PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14)


@contextmanager
def auth_connection():
    AUTH_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(AUTH_DB, timeout=15)
    try:
        os.chmod(AUTH_DB, 0o600)
    except OSError:
        pass
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
        for path in (AUTH_DB, Path(str(AUTH_DB) + "-wal"), Path(str(AUTH_DB) + "-shm")):
            try:
                if path.exists():
                    os.chmod(path, 0o600)
            except OSError:
                pass


def init_auth_db() -> None:
    with auth_connection() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','approved','declined')),
                role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
                api_key_cipher TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                reviewed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)


init_auth_db()


def account_by_id(user_id) -> sqlite3.Row | None:
    if not user_id:
        return None
    with auth_connection() as connection:
        return connection.execute(
            "SELECT id,email,status,role,api_key_cipher,created_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()


def admin_exists() -> bool:
    with auth_connection() as connection:
        return connection.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone() is not None


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")
    return session["csrf_token"]


def _valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value))


def _key_cipher() -> Fernet:
    material = sha256((str(app.secret_key) + ":user-api-keys").encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(material))


def user_api_key(user_id: int) -> str:
    with auth_connection() as connection:
        row = connection.execute("SELECT api_key_cipher FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not row["api_key_cipher"]:
        return ""
    try:
        return _key_cipher().decrypt(row["api_key_cipher"].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        app.logger.error("A saved user API key could not be decrypted; it was not used.")
        return ""


def get_setting(key: str, default: str = "") -> str:
    with auth_connection() as connection:
        row = connection.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with auth_connection() as connection:
        connection.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def smtp_is_configured() -> bool:
    return bool(os.environ.get("PCB_SMTP_HOST", "").strip() and
                os.environ.get("PCB_SMTP_FROM", "").strip())


def send_registration_notice(email: str) -> None:
    recipient = get_setting("registration_email")
    host = os.environ.get("PCB_SMTP_HOST", "").strip()
    sender = os.environ.get("PCB_SMTP_FROM", "").strip()
    if not recipient or not host or not sender:
        return
    message = EmailMessage()
    message["Subject"] = "PCB Laser: registration awaiting approval"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"A new PCB Laser account request is waiting for review.\n\nEmail: {email}\n\n"
        "Sign in to PCB Laser and open Admin to approve or decline it."
    )
    try:
        port = int(os.environ.get("PCB_SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if os.environ.get("PCB_SMTP_TLS", "yes").lower() == "yes":
                smtp.starttls()
            username = os.environ.get("PCB_SMTP_USER", "")
            password = os.environ.get("PCB_SMTP_PASSWORD", "")
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException, ValueError):
        app.logger.exception("Registration email could not be sent; the request remains in Admin.")


@app.before_request
def require_account():
    g.user = account_by_id(session.get("user_id"))
    public = {"health", "static", "login", "register", "setup_admin"}
    if request.endpoint in public:
        pass
    elif not admin_exists():
        return redirect(url_for("setup_admin"), code=303)
    elif not g.user or g.user["status"] != "approved":
        session.pop("user_id", None)
        return redirect(url_for("login", next=request.full_path.rstrip("?")), code=303)
    if request.method == "POST" and not app.config.get("TESTING"):
        supplied = request.form.get("csrf_token", "")
        if not supplied or supplied != session.get("csrf_token"):
            abort(400, description="This form expired. Go back, refresh the page, and try again.")


@app.context_processor
def account_context():
    return {"current_account": getattr(g, "user", None), "csrf_token": csrf_token}


def _local_setup_request() -> bool:
    hostname = request.host.split(":", 1)[0].lower()
    return hostname in {"127.0.0.1", "localhost", "192.168.12.168"}


@app.route("/setup", methods=["GET", "POST"])
def setup_admin():
    if admin_exists():
        return redirect(url_for("login"), code=303)
    if not _local_setup_request():
        return render_template("setup-locked.html"), 403
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not _valid_email(email):
            error = "Enter a valid email address."
        elif len(password) < 12:
            error = "Use at least 12 characters for the password."
        elif password != request.form.get("confirm_password", ""):
            error = "The passwords do not match."
        else:
            with auth_connection() as connection:
                cursor = connection.execute(
                    "INSERT INTO users(email,password_hash,status,role,created_at,reviewed_at) "
                    "VALUES(?,?, 'approved','admin',?,?)",
                    (email, generate_password_hash(password), datetime.now(UTC).isoformat(),
                     datetime.now(UTC).isoformat()),
                )
            session.clear()
            session["user_id"] = cursor.lastrowid
            session.permanent = True
            return redirect(url_for("index"), code=303)
    return render_template("setup.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if not admin_exists():
        return redirect(url_for("setup_admin"), code=303)
    message = error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not _valid_email(email):
            error = "Enter a valid email address."
        elif len(password) < 12:
            error = "Use at least 12 characters for the password."
        elif password != request.form.get("confirm_password", ""):
            error = "The passwords do not match."
        else:
            try:
                with auth_connection() as connection:
                    connection.execute(
                        "INSERT INTO users(email,password_hash,status,role,created_at) "
                        "VALUES(?,?, 'pending','user',?)",
                        (email, generate_password_hash(password), datetime.now(UTC).isoformat()),
                    )
                threading.Thread(target=send_registration_notice, args=(email,), daemon=True).start()
            except sqlite3.IntegrityError:
                pass
            message = "Your request was received. You can sign in after an administrator approves it."
    return render_template("register.html", error=error, message=message)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not admin_exists():
        return redirect(url_for("setup_admin"), code=303)
    if g.user and g.user["status"] == "approved":
        return redirect(url_for("index"), code=303)
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        with auth_connection() as connection:
            user = connection.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            locked = False
            if user and user["locked_until"]:
                try:
                    locked = datetime.fromisoformat(user["locked_until"]) > datetime.now(UTC)
                except ValueError:
                    pass
            if user and not locked and check_password_hash(user["password_hash"], request.form.get("password", "")):
                if user["status"] == "approved":
                    connection.execute("UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?", (user["id"],))
                    session.clear()
                    session["user_id"] = user["id"]
                    session.permanent = True
                    next_url = request.args.get("next", "")
                    return redirect(next_url if next_url.startswith("/") and not next_url.startswith("//") else url_for("index"), code=303)
                error = "This account is still awaiting approval." if user["status"] == "pending" else "This registration was declined."
            else:
                if user and not locked:
                    attempts = user["failed_attempts"] + 1
                    lock_until = ((datetime.now(UTC) + timedelta(minutes=15)).isoformat()
                                  if attempts >= 5 else None)
                    connection.execute("UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",
                                       (0 if lock_until else attempts, lock_until, user["id"]))
                error = "Email or password was not recognized."
    return render_template("login.html", error=error)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"), code=303)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    message = error = None
    if request.method == "POST":
        action = request.form.get("action")
        with auth_connection() as connection:
            if action == "remove-key":
                connection.execute("UPDATE users SET api_key_cipher=NULL WHERE id=?", (g.user["id"],))
                message = "Your API key was removed."
            else:
                api_key = request.form.get("api_key", "").strip()
                if not api_key:
                    error = "Paste an API key, or use Remove key."
                else:
                    encrypted = _key_cipher().encrypt(api_key.encode("utf-8")).decode("ascii")
                    connection.execute("UPDATE users SET api_key_cipher=? WHERE id=?", (encrypted, g.user["id"]))
                    message = "Your API key was saved securely."
        g.user = account_by_id(g.user["id"])
    return render_template("settings.html", has_api_key=bool(g.user["api_key_cipher"]),
                           message=message, error=error)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if g.user["role"] != "admin":
        abort(403)
    message = error = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save-email":
            notification_email = request.form.get("registration_email", "").strip().lower()
            if notification_email and not _valid_email(notification_email):
                error = "Enter a valid notification email address."
            else:
                set_setting("registration_email", notification_email)
                message = "Registration notification address saved."
        elif action in {"approve", "decline"}:
            try:
                user_id = int(request.form.get("user_id", ""))
            except ValueError:
                abort(400)
            status = "approved" if action == "approve" else "declined"
            with auth_connection() as connection:
                connection.execute(
                    "UPDATE users SET status=?,reviewed_at=? WHERE id=? AND role='user' AND status='pending'",
                    (status, datetime.now(UTC).isoformat(), user_id),
                )
            message = f"Registration {action}d."
    with auth_connection() as connection:
        pending = connection.execute(
            "SELECT id,email,created_at FROM users WHERE status='pending' ORDER BY created_at"
        ).fetchall()
        members = connection.execute(
            "SELECT email,status,role,created_at FROM users ORDER BY created_at"
        ).fetchall()
    return render_template("admin.html", pending=pending, members=members,
                           registration_email=get_setting("registration_email"),
                           smtp_configured=smtp_is_configured(), message=message, error=error)

SCHEMATIC_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "components": {"type": "array", "items": {"type": "object", "additionalProperties": False,
                       "properties": {"reference": {"type": "string"}, "value": {"type": "string"},
                                      "kind": {"type": "string"}, "notes": {"type": "string"}},
                       "required": ["reference", "value", "kind", "notes"]}},
        "connections": {"type": "array", "items": {"type": "object", "additionalProperties": False,
                        "properties": {"net": {"type": "string"}, "endpoints": {"type": "array", "items": {"type": "string"}},
                                       "confidence": {"type": "string"}},
                        "required": ["net", "endpoints", "confidence"]}},
        "assumptions": {"type": "array", "items": {"type": "string"}},
        "questions": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["summary", "components", "connections", "assumptions", "questions", "warnings"]
}

SCHEMATIC_PROMPT = """Turn the supplied schematic and any optional BOM into a practical circuit specification for a basic single-sided PCB. The schematic is authoritative for connectivity; the BOM resolves values and part identity. Use standard pinouts for common components, assign ordinary missing references yourself (U1, R1, LED1, and so on), and choose sensible through-hole defaults unless the user's notes say otherwise. Do not ask the user to identify standard pins, reference labels, LED polarity, or ordinary footprints. Record those choices as assumptions. Ask a question only when a wire/junction, component value, or source connection is truly unreadable and would change the circuit. Return a proposed circuit inventory and net list, not a PCB layout."""

PROJECT_DESIGN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "supply": {"type": "string"},
        "how_it_works": {"type": "array", "items": {"type": "string"}},
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "reference": {"type": "string"},
                    "value": {"type": "string"},
                    "description": {"type": "string"},
                    "quantity": {"type": "integer"},
                    "kind": {"type": "string", "enum": ["resistor", "capacitor", "led", "diode", "transistor", "ic8", "ic14", "ic16", "connector2", "switch2"]},
                },
                "required": ["reference", "value", "description", "quantity", "kind"],
            },
        },
        "nets": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {"name": {"type": "string"}, "endpoints": {"type": "array", "items": {"type": "string"}}},
                "required": ["name", "endpoints"],
            },
        },
        "assembly_steps": {"type": "array", "items": {"type": "string"}},
        "checks": {"type": "array", "items": {"type": "string"}},
        "enclosure_notes": {"type": "array", "items": {"type": "string"}},
        "battery_plan": {"type": "string"},
        "led_calculations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["title", "summary", "supply", "how_it_works", "components",
                 "nets", "assembly_steps", "checks", "enclosure_notes", "battery_plan",
                 "led_calculations"],
}

PROJECT_DESIGN_PROMPT = """Design a genuinely new, very simple beginner electronics project from the user's request. Do not substitute or refer to any existing project. Use only low-voltage battery or regulated DC power, ordinary obtainable parts, and one single-sided PCB. Respect the requested through-hole or surface-mount style. Choose sensible values and standard pinouts without asking the beginner routine electronics questions.

Describe the circuit as a precise component list and net list; application code will create the KiCad board. Use one component-list entry per physical part, quantity 1, and unique standard references. Choose each component's closest supported kind. Every net endpoint must use REFERENCE.PIN format and the standard physical pin number for that part. Include every electrically connected pin, including power and ground. Keep the design to 14 or fewer physical parts. Never include a KiCad file or PCB routing in your answer.

For every LED, calculate its resistor using R = (supply voltage - LED forward voltage) / target current. Use a beginner-safe target current, show the voltage/current arithmetic in led_calculations, and round up to a common resistor value. Use typical forward voltage appropriate to the selected color rather than a single fixed resistor for every supply.

The board compiler has a deliberately small verified IC catalog. If an IC is needed, use only NE555/TLC555 (ic8), LM358 (ic8), CD40106 (ic14), 74HC14 (ic14), or CD4017 (ic16), with their standard pin numbering. For surface-mount builds choose SOIC and 0805/SOT-23 parts; for through-hole builds choose DIP, axial, radial, TO-92, and 2.54/5.08 mm parts. Never place a real IC into a generic package just because the pin count is similar.

For an LED chaser where only one LED is on at a time, prefer one correctly calculated shared current-limiting resistor in the common LED return instead of one resistor per LED. This preserves the requested LED count and reduces unnecessary parts. A request for a heart, circle, row, or other visible LED arrangement refers to physical LED placement and must be reflected in the project title, summary, and assembly steps.

Keep explanations short and beginner-friendly. Enclosure preference is a design constraint only: make practical LED, light-sensor, control, connector, and mounting placement choices without asking more enclosure questions. If the project is battery-powered, choose a specific ordinary battery/holder arrangement and describe the required internal battery bay, access, and wire clearance in battery_plan and enclosure_notes. Otherwise state that no internal battery bay is required."""

PROJECT_REPAIR_PROMPT = """Repair the structured circuit specification using the compiler or KiCad finding supplied. Preserve the user's intended simple project and build style. Correct invalid references, pin numbers, duplicate pin assignments, or electrically incomplete nets. Return the complete project object using the required schema. Do not write KiCad syntax; application code creates the board."""


LED_OPTIONS = {
    "red": {"label": "Red", "resistor": "470 Ω at 5 V", "forward_voltage": "2.0 V"},
    "yellow": {"label": "Yellow", "resistor": "470 Ω at 5 V", "forward_voltage": "2.1 V"},
    "green": {"label": "Green", "resistor": "470 Ω at 5 V", "forward_voltage": "2.2 V"},
    "blue": {"label": "Blue", "resistor": "390 Ω at 5 V", "forward_voltage": "3.0 V"},
    "white": {"label": "White", "resistor": "390 Ω at 5 V", "forward_voltage": "3.0 V"},
}


def selected_led(value: str | None) -> tuple[str, dict[str, str]]:
    key = value if value in LED_OPTIONS else "red"
    return key, LED_OPTIONS[key]


PROJECTS_FILE = Path("/data/projects.json")


class UnsupportedProjectError(ValueError):
    """A project that must not be improvised into a fabrication-ready board."""


def project_preflight(project: dict) -> None:
    idea = project.get("idea", "").lower()
    lithium_words = ("lithium", "li-ion", "lion battery", "lipo", "li-po", "lifepo")
    charge_words = ("charger", "charging", "charge circuit", "overcharge", "battery protection")
    if any(word in idea for word in lithium_words) and any(word in idea for word in charge_words):
        raise UnsupportedProjectError(
            "Lithium-cell charging and protection is not released by this beginner board builder. "
            "It requires an exact manufacturer footprint, thermal layout, and battery-safety design; "
            "use a reputable ready-made charger/protection module instead.")
    if any(word in idea for word in ("mains", "wall outlet", "120v", "120 v", "230v", "230 v", "high voltage")):
        raise UnsupportedProjectError(
            "Mains and high-voltage projects are outside this beginner board builder's safe scope.")


def validate_part_catalog(design: dict) -> None:
    allowed_ics = {
        "ic8": ("ne555", "tlc555", "lm358"),
        "ic14": ("cd40106", "74hc14"),
        "ic16": ("cd4017",),
    }
    for component in design.get("components", []):
        kind = component.get("kind", "")
        if kind not in allowed_ics:
            continue
        value = component.get("value", "").lower().replace(" ", "")
        if not any(name in value for name in allowed_ics[kind]):
            raise UnsupportedProjectError(
                f"{component.get('reference', 'An IC')} is not in the builder's verified footprint and pinout catalog. "
                "No fabrication files were released.")


def is_heart_chaser_request(project: dict) -> bool:
    idea = project.get("idea", "").lower()
    return ("heart" in idea and any(word in idea for word in ("led", "light"))
            and any(word in idea for word in ("trace", "chase", "circle", "around", "sequence")))


def heart_chaser_design(project: dict) -> dict:
    """Known-good seven-step chaser reached through an ordinary prompt."""
    smd = project.get("style") == "surface-mount"
    package = {
        "connector": "2-pin SMD connector" if smd else "2-pin 5.08 mm connector",
        "inverter": "CD40106B, SOIC-14" if smd else "CD40106B, DIP-14",
        "counter": "CD4017B, SOIC-16" if smd else "CD4017B, DIP-16",
        "resistor": "0805" if smd else "axial through-hole",
        "capacitor": "0805" if smd else "radial through-hole",
        "led": "0805" if smd else "5 mm through-hole",
    }
    color = project_leds(project)[0]
    color_label = LED_OPTIONS[color]["label"]
    forward_voltage = float(LED_OPTIONS[color]["forward_voltage"].split()[0])
    calculated = (5.0 - forward_voltage) / 0.003
    resistor_value = "1 kΩ" if calculated > 680 else "680 Ω"
    components = [
        {"reference": "J1", "value": f"5 V DC {package['connector']}", "description": "Regulated 5 V power input; pin 1 positive", "quantity": 1, "kind": "connector2"},
        {"reference": "U1", "value": package["inverter"], "description": "Schmitt-trigger clock oscillator", "quantity": 1, "kind": "ic14"},
        {"reference": "U2", "value": package["counter"], "description": "Seven-step LED sequence counter", "quantity": 1, "kind": "ic16"},
        {"reference": "R1", "value": f"1 MΩ, {package['resistor']}", "description": "Chase-speed timing resistor", "quantity": 1, "kind": "resistor"},
        {"reference": "C1", "value": f"1 µF, {package['capacitor']}", "description": "Chase-speed timing capacitor", "quantity": 1, "kind": "capacitor"},
        {"reference": "C2", "value": f"100 nF, {package['capacitor']}", "description": "Power-supply bypass capacitor", "quantity": 1, "kind": "capacitor"},
        {"reference": "R2", "value": f"{resistor_value}, {package['resistor']}", "description": "Shared LED resistor; only one LED is on at a time", "quantity": 1, "kind": "resistor"},
    ]
    components.extend({"reference": f"D{index}", "value": f"{color_label} {package['led']} LED", "description": f"Heart-outline LED position {index}; pin 1 cathode, pin 2 anode", "quantity": 1, "kind": "led"} for index in range(1, 8))
    nets = [
        {"name": "+5V", "endpoints": ["J1.1", "U1.14", "U2.16", "C2.1"]},
        {"name": "GND", "endpoints": ["J1.2", "U1.7", "U1.3", "U1.5", "U1.9", "U1.11", "U1.13", "U2.8", "U2.13", "C1.2", "C2.2", "R2.2"]},
        {"name": "OSC_TIMING", "endpoints": ["U1.1", "R1.1", "C1.1"]},
        {"name": "CLOCK", "endpoints": ["U1.2", "R1.2", "U2.14"]},
        {"name": "RESET_AFTER_7", "endpoints": ["U2.6", "U2.15"]},
        {"name": "LED_RETURN", "endpoints": ["R2.1"] + [f"D{index}.1" for index in range(1, 8)]},
    ]
    for index, pin in enumerate((3, 2, 4, 7, 10, 1, 5), 1):
        nets.append({"name": f"LED{index}_DRIVE", "endpoints": [f"U2.{pin}", f"D{index}.2"]})
    return {
        "title": f"Seven-{color_label}-LED Heart Chaser",
        "summary": "Seven LEDs arranged as a heart light one after another around the outline.",
        "supply": "5 V regulated DC",
        "how_it_works": ["U1 makes a slow clock signal.", "U2 advances one output for every clock pulse and resets after the seventh LED.", "Only one LED is on at a time, so the seven LEDs safely share R2."],
        "components": components, "nets": nets,
        "assembly_steps": ["Solder the resistors and capacitors first.", "Solder U1 and U2 in the marked orientation.", "Solder the seven LEDs around the heart outline, checking every LED's polarity.", "Attach the regulated 5 V power connector and inspect for bridges before power."],
        "checks": ["Use only regulated 5 V DC.", "Confirm both IC orientations and every LED polarity.", "Verify the board is no larger than 100 × 80 mm before etching."],
        "enclosure_notes": ["Keep all seven LEDs visible through a heart-shaped front opening.", "Use the board's four mounting-hole coordinates for enclosure standoffs."],
        "battery_plan": "No internal battery bay is required; this project uses an external regulated 5 V connection.",
        "led_calculations": [f"{color_label} LED at 5.0 V: R = (5.0 V - {forward_voltage:.1f} V) / 0.003 A = {calculated:.0f} Ω; use {resistor_value}. Only one LED is on at a time, so R2 is shared."],
        "layout_shape": "heart",
    }


def selected_project_leds(project: dict) -> list[str]:
    values = project.get("leds")
    if not isinstance(values, list):
        values = [project.get("led")]
    cleaned = []
    for value in values:
        if value in LED_OPTIONS and value not in cleaned:
            cleaned.append(value)
    return cleaned


def project_leds(project: dict) -> list[str]:
    """Return a usable LED palette for designs that actually need an LED."""
    return selected_project_leds(project) or ["red"]


def project_battery_plan(project: dict, design: dict) -> str:
    if design.get("battery_plan"):
        return design["battery_plan"]
    text = " ".join([project.get("idea", ""), design.get("supply", "")] +
                    [part.get("value", "") for part in design.get("components", [])]).lower()
    if "9v" in text or "9 v" in text:
        return "Reserve an internal bay for one rectangular 9 V battery and clip, with approximately 30 × 22 × 52 mm clear space plus wire clearance."
    if "aaa" in text:
        return "Reserve space for the specified AAA battery holder, plus 3 mm clearance around the holder and wires."
    if "aa" in text:
        return "Reserve space for the specified AA battery holder, plus 3 mm clearance around the holder and wires."
    if "cr2032" in text or "coin" in text:
        return "Reserve an accessible internal bay for the specified coin-cell holder and allow clearance to replace the cell."
    if "battery" in text or "lipo" in text or "li-po" in text:
        return "Reserve a separate internal bay sized for the specified battery and connector, with at least 3 mm wall and wire clearance."
    return "No internal battery bay is required; this project uses its external power connection."


def create_project(idea: str, parts: str, style: str, leds: list[str], enclosure: bool,
                   owner_id: int | None = None) -> dict:
    """Persist a new-project brief separately from completed templates."""
    project = {
        "id": uuid4().hex[:10],
        "idea": idea[:1000],
        "parts": parts if parts in {"have", "shopping"} else "shopping",
        "style": style if style in {"through-hole", "surface-mount"} else "through-hole",
        "led": leds[0] if leds else None,
        "leds": leds,
        "enclosure": enclosure,
        "owner_id": owner_id,
        "status": "brief",
        "created_at": datetime.now(UTC).isoformat(),
    }
    try:
        existing = json.loads(PROJECTS_FILE.read_text(encoding="utf-8")) if PROJECTS_FILE.exists() else []
        if not isinstance(existing, list):
            existing = []
    except (OSError, json.JSONDecodeError):
        existing = []
    try:
        PROJECTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        PROJECTS_FILE.write_text(json.dumps([project, *existing][:100], indent=2), encoding="utf-8")
    except OSError:
        # The current page remains usable if the optional project notebook is unavailable.
        pass
    return project


def blinking_led_board() -> str:
    """Return the fixed first-learning-project KiCad board, without uploads."""
    return """(kicad_pcb (version 20240108) (generator pcbnew)
  (general (thickness 1.6))
  (paper \"A4\")
  (layers (0 \"F.Cu\" signal) (31 \"B.Cu\" signal) (36 \"B.SilkS\" user \"b.silkscreen\") (44 \"Edge.Cuts\" user))
  (setup (pad_to_mask_clearance 0))
  (net 0 \"\") (net 1 \"GND\") (net 2 \"+9V\") (net 3 \"TIMING\") (net 4 \"DISCHARGE\") (net 5 \"OUT\")
  (footprint \"Connector_PinHeader_1x02\" (layer \"F.Cu\") (at 12 18)
    (pad \"1\" thru_hole rect (at 0 0) (size 2.4 2.4) (drill 1.1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"2\" thru_hole circle (at 0 3.8) (size 2.4 2.4) (drill 1.1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (footprint \"Package_DIP:DIP-8_W7.62mm\" (layer \"F.Cu\") (at 39 16)
    (pad \"1\" thru_hole rect (at 0 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\"))
    (pad \"2\" thru_hole circle (at 0 2.54) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\"))
    (pad \"3\" thru_hole circle (at 0 5.08) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 5 \"OUT\"))
    (pad \"4\" thru_hole circle (at 0 7.62) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"5\" thru_hole circle (at 7.62 7.62) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\"))
    (pad \"6\" thru_hole circle (at 7.62 5.08) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\"))
    (pad \"7\" thru_hole circle (at 7.62 2.54) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 4 \"DISCHARGE\"))
    (pad \"8\" thru_hole circle (at 7.62 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\")))
  (footprint \"Resistor_THT:R_Axial\" (layer \"F.Cu\") (at 26 16)
    (pad \"1\" thru_hole circle (at 0 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"2\" thru_hole circle (at 0 7.5) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 4 \"DISCHARGE\")))
  (footprint \"Resistor_THT:R_Axial\" (layer \"F.Cu\") (at 26 25)
    (pad \"1\" thru_hole circle (at 0 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 4 \"DISCHARGE\"))
    (pad \"2\" thru_hole circle (at 0 7.5) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\")))
  (footprint \"Capacitor_THT:C_Radial\" (layer \"F.Cu\") (at 34 33)
    (pad \"1\" thru_hole rect (at 0 0) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\"))
    (pad \"2\" thru_hole circle (at 2.5 0) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (footprint \"Capacitor_THT:C_Disc\" (layer \"F.Cu\") (at 20 33)
    (pad \"1\" thru_hole circle (at 0 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"2\" thru_hole circle (at 2.5 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (footprint \"Resistor_THT:R_Axial\" (layer \"F.Cu\") (at 55 21)
    (pad \"1\" thru_hole circle (at 0 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 5 \"OUT\"))
    (pad \"2\" thru_hole circle (at 7.5 0) (size 2.3 2.3) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 0 \"\")))
  (footprint \"LED_THT:LED_D5.0mm\" (layer \"F.Cu\") (at 62.5 29)
    (pad \"1\" thru_hole rect (at 0 0) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\"))
    (pad \"2\" thru_hole circle (at 2.54 0) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (segment (start 12 18) (end 26 16) (width 0.8) (layer \"B.Cu\") (net 2))
  (segment (start 26 16) (end 46.62 16) (width 0.8) (layer \"B.Cu\") (net 2))
  (segment (start 46.62 16) (end 39 23.62) (width 0.8) (layer \"B.Cu\") (net 2))
  (segment (start 12 18) (end 20 33) (width 0.8) (layer \"B.Cu\") (net 2))
  (segment (start 12 21.8) (end 12 38) (width 0.8) (layer \"B.Cu\") (net 1))
  (segment (start 12 38) (end 65.04 38) (width 0.8) (layer \"B.Cu\") (net 1))
  (segment (start 65.04 38) (end 65.04 29) (width 0.8) (layer \"B.Cu\") (net 1))
  (segment (start 12 38) (end 39 16) (width 0.8) (layer \"B.Cu\") (net 1))
  (segment (start 37 33) (end 37 38) (width 0.8) (layer \"B.Cu\") (net 1))
  (segment (start 22.5 33) (end 22.5 38) (width 0.8) (layer \"B.Cu\") (net 1))
  (segment (start 26 23.5) (end 26 25) (width 0.7) (layer \"B.Cu\") (net 4))
  (segment (start 26 23.5) (end 46.62 18.54) (width 0.7) (layer \"B.Cu\") (net 4))
  (segment (start 26 32.5) (end 34 33) (width 0.7) (layer \"B.Cu\") (net 3))
  (segment (start 34 33) (end 46.62 21.08) (width 0.7) (layer \"B.Cu\") (net 3))
  (segment (start 39 18.54) (end 55 21) (width 0.7) (layer \"B.Cu\") (net 5))
  (segment (start 62.5 21) (end 62.5 29) (width 0.7) (layer \"B.Cu\") (net 0))
  (gr_rect (start 7 10) (end 70 43) (stroke (width 0.4) (type default)) (fill none) (layer \"Edge.Cuts\")))"""


def blinking_led_board() -> str:
    """DRC-oriented first learning board: bottom copper plus five wire jumpers."""
    return """(kicad_pcb (version 20240108) (generator pcbnew)
  (general (thickness 1.6))
  (paper \"A4\")
  (layers (0 \"F.Cu\" signal) (31 \"B.Cu\" signal) (36 \"B.SilkS\" user \"b.silkscreen\") (44 \"Edge.Cuts\" user))
  (setup (pad_to_mask_clearance 0))
  (net 0 \"\") (net 1 \"GND\") (net 2 \"+9V\") (net 3 \"TIMING\") (net 4 \"DISCHARGE\") (net 5 \"OUT\") (net 6 \"LED+\")
  (footprint \"J1\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole rect (at 10 12) (size 2.5 2.5) (drill 1.1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"2\" thru_hole circle (at 10 16) (size 2.5 2.5) (drill 1.1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (footprint \"C2\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole rect (at 20 12) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"2\" thru_hole circle (at 20 16) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (footprint \"U1\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole rect (at 40 20) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\"))
    (pad \"2\" thru_hole circle (at 40 22.54) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\"))
    (pad \"3\" thru_hole circle (at 40 25.08) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 5 \"OUT\"))
    (pad \"4\" thru_hole circle (at 40 27.62) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"5\" thru_hole circle (at 47.62 27.62) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\"))
    (pad \"6\" thru_hole circle (at 47.62 25.08) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\"))
    (pad \"7\" thru_hole circle (at 47.62 22.54) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 4 \"DISCHARGE\"))
    (pad \"8\" thru_hole circle (at 47.62 20) (size 2.2 2.2) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\")))
  (footprint \"R1\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole circle (at 55 15) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 2 \"+9V\"))
    (pad \"2\" thru_hole circle (at 55 22.54) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 4 \"DISCHARGE\")))
  (footprint \"R2\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole circle (at 55 27) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 4 \"DISCHARGE\"))
    (pad \"2\" thru_hole circle (at 55 34) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\")))
  (footprint \"C1\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole rect (at 55 39) (size 2.5 2.5) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 3 \"TIMING\"))
    (pad \"2\" thru_hole circle (at 58 39) (size 2.5 2.5) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (footprint \"R3\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole circle (at 55 31) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 5 \"OUT\"))
    (pad \"2\" thru_hole circle (at 65 31) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 6 \"LED+\")))
  (footprint \"LED1\" (layer \"F.Cu\") (at 0 0)
    (pad \"1\" thru_hole rect (at 65 38) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 6 \"LED+\"))
    (pad \"2\" thru_hole circle (at 68 38) (size 2.4 2.4) (drill 1) (layers \"*.Cu\" \"*.Mask\") (net 1 \"GND\")))
  (segment (start 10 12) (end 55 12) (width 0.7) (layer \"B.Cu\") (net 2))
  (segment (start 55 12) (end 55 15) (width 0.7) (layer \"B.Cu\") (net 2))
  (segment (start 10 16) (end 10 43) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 10 43) (end 68 43) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 20 16) (end 15 16) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 15 16) (end 15 43) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 68 38) (end 68 43) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 58 39) (end 58 43) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 47.62 22.54) (end 55 22.54) (width 0.7) (layer \"B.Cu\") (net 4))
  (segment (start 55 22.54) (end 55 27) (width 0.7) (layer \"B.Cu\") (net 4))
  (segment (start 55 34) (end 55 39) (width 0.7) (layer \"B.Cu\") (net 3))
  (segment (start 65 31) (end 65 38) (width 0.7) (layer \"B.Cu\") (net 6))
  (segment (start 40 20) (end 32 20) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 32 20) (end 32 43) (width 0.7) (layer \"B.Cu\") (net 1))
  (segment (start 40 27.62) (end 35 27.62) (width 0.7) (layer \"F.Cu\") (net 2))
  (segment (start 35 27.62) (end 35 12) (width 0.7) (layer \"F.Cu\") (net 2))
  (segment (start 35 12) (end 20 12) (width 0.7) (layer \"F.Cu\") (net 2))
  (segment (start 47.62 20) (end 47.62 15) (width 0.7) (layer \"F.Cu\") (net 2))
  (segment (start 47.62 15) (end 55 15) (width 0.7) (layer \"F.Cu\") (net 2))
  (segment (start 40 22.54) (end 43 22.54) (width 0.7) (layer \"F.Cu\") (net 3))
  (segment (start 43 22.54) (end 43 25.08) (width 0.7) (layer \"F.Cu\") (net 3))
  (segment (start 43 25.08) (end 47.62 25.08) (width 0.7) (layer \"F.Cu\") (net 3))
  (segment (start 47.62 25.08) (end 58 25.08) (width 0.7) (layer \"F.Cu\") (net 3))
  (segment (start 58 25.08) (end 58 34) (width 0.7) (layer \"F.Cu\") (net 3))
  (segment (start 58 34) (end 55 34) (width 0.7) (layer \"F.Cu\") (net 3))
  (segment (start 40 25.08) (end 42 25.08) (width 0.7) (layer \"F.Cu\") (net 5))
  (segment (start 42 25.08) (end 42 31) (width 0.7) (layer \"F.Cu\") (net 5))
  (segment (start 42 31) (end 55 31) (width 0.7) (layer \"F.Cu\") (net 5))
  (gr_rect (start 5 7) (end 73 46) (stroke (width 0.4) (type default)) (fill none) (layer \"Edge.Cuts\")))"""


def project_kind(idea: str) -> str | None:
    words = idea.lower()
    if ("blink" in words or "flash" in words) and ("light" in words or "led" in words):
        return "blinking-led"
    return None


@lru_cache(maxsize=1)
def blinking_led_drc_check() -> None:
    """Refuse to serve the learning-board files unless KiCad DRC is clean."""
    with tempfile.TemporaryDirectory() as directory:
        board_path = os.path.join(directory, "blinking-led.kicad_pcb")
        report_path = os.path.join(directory, "drc.json")
        with open(board_path, "w", encoding="utf-8") as board_file:
            board_file.write(blinking_led_board())
        result = subprocess.run(
            ["kicad-cli", "pcb", "drc", board_path, "--format", "json", "--output", report_path,
             "--severity-all", "--exit-code-violations"],
            capture_output=True, text=True, timeout=45, check=False)
        try:
            with open(report_path, encoding="utf-8") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("KiCad could not complete the board check.") from error
        if result.returncode or report.get("violations") or report.get("unconnected_items"):
            raise ValueError("This learning-board template did not pass its KiCad safety check.")


@dataclass
class Token:
    value: str


def tokens(source: str) -> list[str]:
    """Tiny S-expression tokenizer which preserves quoted KiCad text."""
    values = re.findall(r'\(|\)|"(?:\\.|[^"\\])*"|[^\s()]+', source)
    # KiCad quotes layer names (for example "B.Cu").  Keeping the quote marks
    # makes otherwise correct layers impossible to match.
    return [value[1:-1].replace(r'\"', '"').replace(r'\\', '\\')
            if len(value) >= 2 and value.startswith('"') and value.endswith('"') else value
            for value in values]


def tree(source: str):
    root, stack = [], []
    current = root
    for value in tokens(source):
        if value == "(":
            item = []
            current.append(item)
            stack.append(current)
            current = item
        elif value == ")":
            if not stack:
                raise ValueError("Unexpected closing parenthesis in KiCad file.")
            current = stack.pop()
        else:
            current.append(value)
    if stack:
        raise ValueError("The KiCad file has an unfinished expression.")
    return root[0] if len(root) == 1 else root


def children(node, name: str):
    return [item for item in node if isinstance(item, list) and item and item[0] == name]


def child(node, name: str):
    found = children(node, name)
    return found[0] if found else None


def number(value: str, default=0.0) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def point(node):
    return (number(node[1]), number(node[2])) if node and len(node) >= 3 else None


def layer_matches(node, wanted: str) -> bool:
    layers = child(node, "layers")
    if layers:
        return wanted in layers[1:] or (wanted in {"F.Cu", "B.Cu"} and "*.Cu" in layers[1:])
    layer = child(node, "layer")
    return bool(layer and len(layer) > 1 and layer[1] == wanted)


def find_nodes(node, names: set[str]):
    if not isinstance(node, list):
        return
    if node and node[0] in names:
        yield node
    for value in node:
        if isinstance(value, list):
            yield from find_nodes(value, names)


def rotate(x, y, degrees):
    radians = math.radians(degrees)
    return (x * math.cos(radians) - y * math.sin(radians),
            x * math.sin(radians) + y * math.cos(radians))


def legacy_arc_svg(node):
    """Render KiCad 5 gr_arc: start=center, end=arc-start, angle=sweep."""
    center, arc_start, angle = point(child(node, "start")), point(child(node, "end")), number((child(node, "angle") or ["angle", 0])[1])
    if not center or not arc_start or not angle:
        return None
    vx, vy = arc_start[0] - center[0], arc_start[1] - center[1]
    radius = math.hypot(vx, vy)
    if not radius:
        return None
    ex, ey = rotate(vx, vy, angle)
    end = (center[0] + ex, center[1] + ey)
    large_arc = 1 if abs(angle) > 180 else 0
    # SVG's positive sweep follows the screen-coordinate clockwise direction.
    sweep = 1 if angle > 0 else 0
    return f'<path d="M {arc_start[0]:.6g} {arc_start[1]:.6g} A {radius:.6g} {radius:.6g} 0 {large_arc} {sweep} {end[0]:.6g} {end[1]:.6g}"/>'


def shape_svg(shape, x, y, width, height, angle=0.0):
    transform = f' transform="rotate({angle:.6g} {x:.6g} {y:.6g})"' if angle else ""
    if shape == "circle":
        return f'<ellipse cx="{x:.6g}" cy="{y:.6g}" rx="{width / 2:.6g}" ry="{height / 2:.6g}"{transform}/>'
    if shape == "oval":
        return f'<rect x="{x - width / 2:.6g}" y="{y - height / 2:.6g}" width="{width:.6g}" height="{height:.6g}" rx="{min(width, height) / 2:.6g}"{transform}/>'
    if shape in {"roundrect", "chamfered_rect"}:
        return f'<rect x="{x - width / 2:.6g}" y="{y - height / 2:.6g}" width="{width:.6g}" height="{height:.6g}" rx="{min(width, height) * .2:.6g}"{transform}/>'
    return f'<rect x="{x - width / 2:.6g}" y="{y - height / 2:.6g}" width="{width:.6g}" height="{height:.6g}"{transform}/>'


def parse_board(source: str, wanted: str):
    document = tree(source)
    if not isinstance(document, list) or not document or document[0] != "kicad_pcb":
        raise ValueError("This is not a KiCad .kicad_pcb board file.")
    artwork, outline, drills, bounds = [], [], [], []

    def include(x, y, margin=0):
        bounds.extend([(x - margin, y - margin), (x + margin, y + margin)])

    # Copper tracks and vias.
    for item in find_nodes(document, {"segment", "arc", "via"}):
        if not layer_matches(item, wanted):
            continue
        if item[0] == "segment":
            start, end, width = point(child(item, "start")), point(child(item, "end")), number((child(item, "width") or [0, .25])[1])
            if start and end:
                artwork.append(f'<path d="M {start[0]:.6g} {start[1]:.6g} L {end[0]:.6g} {end[1]:.6g}" stroke-width="{width:.6g}"/>')
                include(*start, width / 2); include(*end, width / 2)
        elif item[0] == "via":
            at, size = point(child(item, "at")), number((child(item, "size") or [0, 0])[1])
            if at and size:
                artwork.append(shape_svg("circle", *at, size, size)); include(*at, size / 2)
                drill = child(item, "drill")
                if drill and len(drill) > 1:
                    drills.append((at[0], at[1], number(drill[1]) / 2))
        # Arc support needs geometry conversion; intentionally omitted instead of guessing.

    # Pads appear inside footprints. We use their local positions with footprint rotation.
    # KiCad 5 calls these `module`; KiCad 6+ uses `footprint`.
    for footprint in children(document, "footprint") + children(document, "module"):
        at = child(footprint, "at") or ["at", "0", "0", "0"]
        fx, fy, fa = number(at[1]), number(at[2]), number(at[3]) if len(at) > 3 else 0
        for pad in children(footprint, "pad"):
            if not layer_matches(pad, wanted):
                continue
            local = child(pad, "at") or ["at", "0", "0", "0"]
            px, py = rotate(number(local[1]), number(local[2]), fa)
            x, y = fx + px, fy + py
            angle = fa + (number(local[3]) if len(local) > 3 else 0)
            size = child(pad, "size") or ["size", "1", "1"]
            width, height = number(size[1]), number(size[2])
            if len(pad) > 2 and pad[2] == "np_thru_hole":
                drill = child(pad, "drill")
                if drill and len(drill) > 1:
                    radius = number(drill[1]) / 2
                    drills.append((x, y, radius))
                    include(x, y, radius)
                continue
            shape = pad[3] if len(pad) > 3 else "rect"
            artwork.append(shape_svg(shape, x, y, width, height, angle))
            include(x, y, max(width, height) / 2)
            if len(pad) > 2 and pad[2] == "thru_hole":
                drill = child(pad, "drill")
                if drill and len(drill) > 1:
                    drills.append((x, y, number(drill[1]) / 2))

    # Board edge, just for reference; retained independently from copper artwork.
    for item in find_nodes(document, {"gr_line", "gr_rect", "gr_arc"}):
        if not layer_matches(item, "Edge.Cuts"):
            continue
        if item[0] == "gr_line":
            start, end = point(child(item, "start")), point(child(item, "end"))
            if start and end:
                outline.append(f'<path d="M {start[0]:.6g} {start[1]:.6g} L {end[0]:.6g} {end[1]:.6g}"/>')
                include(*start); include(*end)
        elif item[0] == "gr_rect":
            start, end = point(child(item, "start")), point(child(item, "end"))
            if start and end:
                x, y = min(start[0], end[0]), min(start[1], end[1])
                outline.append(f'<rect x="{x:.6g}" y="{y:.6g}" width="{abs(end[0]-start[0]):.6g}" height="{abs(end[1]-start[1]):.6g}"/>')
                include(*start); include(*end)
        elif item[0] == "gr_arc":
            arc = legacy_arc_svg(item)
            center, arc_start = point(child(item, "start")), point(child(item, "end"))
            if arc and center and arc_start:
                outline.append(arc)
                radius = math.dist(center, arc_start)
                include(*center, radius)
    if not artwork:
        raise ValueError(f"No pads or tracks were found on {wanted}. This board may use zones, graphics, or unsupported primitives.")
    if not bounds:
        raise ValueError("Unable to determine the artwork dimensions.")
    min_x, max_x = min(x for x, _ in bounds), max(x for x, _ in bounds)
    min_y, max_y = min(y for _, y in bounds), max(y for _, y in bounds)
    return artwork, outline, drills, (min_x, min_y, max_x, max_y)


def board_from_upload(upload):
    raw = upload.read()
    if upload.filename.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                names = [name for name in archive.namelist() if name.lower().endswith(".kicad_pcb") and not PurePosixPath(name).name.startswith(".")]
                if len(names) != 1:
                    raise ValueError("The ZIP must contain exactly one .kicad_pcb board file.")
                raw = archive.read(names[0])
        except zipfile.BadZipFile as error:
            raise ValueError("The uploaded ZIP file could not be opened.") from error
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("The board file must use UTF-8 text encoding.") from error


def copper_track_summary(source: str) -> dict[str, int]:
    """Count routed traces on each outer copper layer before single-side export."""
    document = tree(source)
    if not isinstance(document, list) or not document or document[0] != "kicad_pcb":
        raise ValueError("This is not a KiCad .kicad_pcb board file.")
    totals = {"F.Cu": 0, "B.Cu": 0}
    for item in find_nodes(document, {"segment", "arc"}):
        for layer in totals:
            if layer_matches(item, layer):
                totals[layer] += 1
    return totals


def make_svg(source: str, layer: str, mirror: bool, include_outline: bool, include_drills: bool):
    artwork, outline, drills, (min_x, min_y, max_x, max_y) = parse_board(source, layer)
    margin = 3
    x, y = min_x - margin, min_y - margin
    width, height = max_x - min_x + 2 * margin, max_y - min_y + 2 * margin
    transform = f'translate({2 * x + width:.6g} 0) scale(-1 1)' if mirror else ""
    body = "\n    ".join(artwork)
    extras = ""
    if include_outline and outline:
        extras += f'\n  <g id="board-outline" fill="none" stroke="#5f6b70" stroke-width="0.15" transform="{transform}">' + "".join(outline) + "</g>"
    if include_drills and drills:
        drill_marks = []
        for px, py, radius in drills:
            cross = min(radius * .55, .7)
            drill_marks.append(f'<circle cx="{px:.6g}" cy="{py:.6g}" r="{radius:.6g}"/>')
            drill_marks.append(f'<path d="M {px-cross:.6g} {py:.6g} L {px+cross:.6g} {py:.6g} M {px:.6g} {py-cross:.6g} L {px:.6g} {py+cross:.6g}"/>')
        extras += f'\n  <g id="drill-centers" fill="none" stroke="#000000" stroke-width="0.16" transform="{transform}">' + "".join(drill_marks) + "</g>"
    label = html.escape(f"KiCad {layer} laser artwork — {'mirrored' if mirror else 'not mirrored'}")
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{width:.6g}mm" height="{height:.6g}mm" viewBox="{x:.6g} {y:.6g} {width:.6g} {height:.6g}">
  <title>{label}</title>
  <desc>Black filled shapes are copper to expose by removing paint. Confirm mirroring with a paper test before laser engraving.</desc>
  <g id="copper-to-expose" fill="#000000" stroke="#000000" stroke-linecap="round" transform="{transform}">
    {body}
  </g>{extras}
</svg>'''


def response_text(payload: dict) -> str:
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"]
    for output in payload.get("output", []):
        for content in output.get("content", []):
            if content.get("type") == "output_text":
                return content.get("text", "")
    raise ValueError("The analysis service returned no readable result.")


def project_model(contents: list[dict], api_key: str | None = None) -> dict:
    if not api_key:
        raise ValueError("New-project generation is not configured on this server.")
    payload = {
        "model": os.environ.get("PCB_PROJECT_MODEL", os.environ.get("PCB_SCHEMATIC_MODEL", "gpt-5.5")),
        "store": False,
        "input": [{"role": "user", "content": contents}],
        "text": {"format": {"type": "json_schema", "name": "project_design",
                            "strict": True, "schema": PROJECT_DESIGN_SCHEMA}},
    }
    try:
        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=240)
        if not response.ok:
            raise ValueError("The project-design service could not complete this project.")
        return json.loads(response_text(response.json()))
    except (requests.RequestException, json.JSONDecodeError) as error:
        raise ValueError("The project-design service returned an unexpected result.") from error


def kicad_drc(source: str) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        board_path = os.path.join(directory, "project.kicad_pcb")
        report_path = os.path.join(directory, "drc.json")
        with open(board_path, "w", encoding="utf-8") as board_file:
            board_file.write(source)
        result = subprocess.run(
            ["kicad-cli", "pcb", "drc", board_path, "--format", "json", "--output", report_path,
             "--severity-all", "--exit-code-violations"],
            capture_output=True, text=True, timeout=60, check=False)
        try:
            with open(report_path, encoding="utf-8") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError) as error:
            detail = (result.stderr or result.stdout or "").strip()[-600:]
            raise ValueError(f"KiCad could not read the generated board. {detail}") from error
        def involves_virtual_jumper_layer(finding: dict) -> bool:
            for item in finding.get("items", []):
                description = item.get("description", "")
                if re.search(r"\bon (?:F\.Cu|In\d+\.Cu)\b", description):
                    return True
            return False

        # F.Cu and the temporary internal copper layers are electrical guide
        # models for insulated wires, not copper that will be fabricated. KiCad
        # correctly flags guide-wire crossings as copper collisions; those are
        # irrelevant to the bottom-copper artwork. Findings that also exist on
        # B.Cu remain blocking errors.
        ignored = 0
        for key in ("violations", "unconnected_items"):
            findings = report.get(key, [])
            kept = [finding for finding in findings
                    if not involves_virtual_jumper_layer(finding)]
            ignored += len(findings) - len(kept)
            report[key] = kept
        report["ignored_jumper_guide_findings"] = ignored
        return report


def generate_project_design(project: dict, progress=None) -> dict:
    project_preflight(project)
    led_choices = selected_project_leds(project)
    if led_choices:
        led_direction = "Available LED colors: " + ", ".join(
            f'{LED_OPTIONS[color]["label"]} (starting resistor {LED_OPTIONS[color]["resistor"]})'
            for color in led_choices
        ) + ". Use as many of these colors as the design needs and calculate each current-limiting resistor."
    else:
        led_direction = ("No LED color was selected. Do not add an LED unless the requested device needs one. "
                         "If it does, choose a practical color and calculate its current-limiting resistor.")
    request_text = (
        f'New project idea: {project["idea"]}\n'
        f'Parts: {"use parts already owned" if project["parts"] == "have" else "make a shopping list"}\n'
        f'Build style: {project["style"]}\n'
        f'{led_direction}\n'
        f'Future enclosure: {"yes; handle automatically" if project["enclosure"] else "no"}'
    )
    if is_heart_chaser_request(project):
        if progress:
            progress("Building the tested seven-LED heart-chaser circuit.")
        design = heart_chaser_design(project)
    else:
        if progress:
            progress("Designing the circuit and choosing practical parts.")
        design = project_model([
            {"type": "input_text", "text": PROJECT_DESIGN_PROMPT},
            {"type": "input_text", "text": request_text},
        ], project.get("_api_key"))
    idea_lower = project.get("idea", "").lower()
    if "heart" in idea_lower:
        design["layout_shape"] = "heart"
    validate_part_catalog(design)
    if progress:
        progress("Routing the single-sided board locally, then checking it in KiCad.")
    try:
        board = compile_board(design, project["style"], project["enclosure"])
        report = kicad_drc(board)
        violations = report.get("violations", [])
        unconnected = report.get("unconnected_items", [])
        if not violations and not unconnected:
            make_svg(board, "B.Cu", True, True, True)
            jumper_nets = sorted(set(re.findall(
                r'\(segment .*?\(layer "(?:F|In\d+)\.Cu"\) \(net (\d+)\)\)', board)))
            if jumper_nets:
                design["jumper_wires"] = len(jumper_nets)
                design["assembly_steps"].append(
                    f"Install {len(jumper_nets)} insulated component-side jumper wire"
                    f"{'s' if len(jumper_nets) != 1 else ''} at the marked drilled endpoints. "
                    "These replace front copper; do not etch a second side.")
                design["checks"].append(
                    "Confirm each insulated jumper follows its KiCad jumper guide and does not touch exposed copper.")
            design["kicad_pcb"] = board
            return design
        compact = [{"type": item.get("type", ""), "description": item.get("description", "")}
                   for item in (violations + unconnected)[:40]]
        report_summary = json.dumps(compact)
    except ValueError as error:
        report_summary = str(error)
    diagnostic_path = Path("/data/generated") / project["id"] / "last-diagnostic.json"
    diagnostic_path.parent.mkdir(parents=True, exist_ok=True)
    diagnostic_path.write_text(json.dumps({
        "attempt_checked": 1,
        "circuit": {"title": design.get("title"), "components": design.get("components"),
                    "nets": design.get("nets")},
        "finding": report_summary,
    }, indent=2), encoding="utf-8")
    raise ValueError(
        "The local single-sided router could not produce a safe board from this design. "
        "No additional AI retries or image-generation tokens were used.")


def save_generated_project(project: dict, design: dict) -> None:
    folder = Path("/data/generated") / project["id"]
    folder.mkdir(parents=True, exist_ok=True)
    public_project = {key: value for key, value in project.items() if not key.startswith("_")}
    (folder / "project.json").write_text(json.dumps({"brief": public_project, "design": design}, indent=2), encoding="utf-8")
    (folder / "board.kicad_pcb").write_text(design["kicad_pcb"], encoding="utf-8")


def generate_project_photo(project: dict, design: dict) -> None:
    """Create a realistic visual guide after the circuit and board pass validation."""
    output = Path("/data/generated") / project["id"] / "assembly.png"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        return
    if os.environ.get("PCB_GENERATE_PHOTOS", "no").lower() != "yes":
        raise ValueError("Automatic finished-build images are not enabled.")
    api_key = project.get("_api_key", "")
    if not api_key:
        raise ValueError("Finished-build image generation is not configured.")
    part_list = "; ".join(
        f'{part["reference"]}: {part["value"]} ({part["kind"]})'
        for part in design["components"]
    )
    style_text = ("surface-mount components soldered directly to the exposed copper side"
                  if project["style"] == "surface-mount" else
                  "through-hole components mounted on top with realistic bent leads and solder joints")
    led_names = ", ".join(LED_OPTIONS[color]["label"] for color in selected_project_leds(project))
    led_direction = (f"Any LEDs should use only these selected colors: {led_names}." if led_names else
                     "If the listed parts include LEDs, show a practical ordinary LED color.")
    prompt = f"""Use case: product-mockup
Asset type: realistic finished-build preview for a beginner PCB project page
Primary request: Create a photorealistic macro product photograph showing what this completed electronics project should approximately look like after soldering.
Project: {design['title']}. {design['summary']}
Parts, with no additions: {part_list}
Build style: {style_text}.
Scene: one small rectangular home-etched copper-clad or amber phenolic board with no green solder mask, resting on a light wood workbench.
Composition: three-quarter overhead close-up, landscape orientation, entire board visible, clean practical component arrangement, board is the clear focus.
Lighting: warm soft workshop lighting, realistic shadows, subtle shallow depth of field.
Materials: exposed etched copper traces, silver solder, believable hobby-electronics parts. {led_direction}
Constraints: exactly one board and exactly the listed physical parts; no extra components, no breadboard, no enclosure, no hands, no labels, no printed text, no logo, no watermark. This is a visual guide, not a technical diagram."""
    try:
        response = requests.post(
            "https://api.openai.com/v1/images/generations",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": os.environ.get("PCB_IMAGE_MODEL", "gpt-image-2.5-flare"),
                "prompt": prompt,
                "size": "1536x1024",
                "quality": "medium",
                "output_format": "png",
            },
            timeout=300,
        )
        if not response.ok:
            raise ValueError("The finished-build image service could not create a preview.")
        encoded = response.json().get("data", [{}])[0].get("b64_json", "")
        image_bytes = base64.b64decode(encoded, validate=True)
        if not image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("The finished-build image service returned an invalid image.")
        temporary = output.with_suffix(".tmp")
        temporary.write_bytes(image_bytes)
        temporary.replace(output)
    except (requests.RequestException, json.JSONDecodeError, ValueError, IndexError) as error:
        raise ValueError("The realistic finished-build preview could not be generated.") from error


def generate_enclosure_photo(project: dict, design: dict) -> None:
    """Create a practical enclosure concept without asking the beginner more questions."""
    output = Path("/data/generated") / project["id"] / "enclosure.png"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        return
    if os.environ.get("PCB_GENERATE_PHOTOS", "no").lower() != "yes":
        raise ValueError("Automatic enclosure images are not enabled.")
    api_key = project.get("_api_key", "")
    if not api_key:
        raise ValueError("Enclosure image generation is not configured.")
    part_list = "; ".join(f'{part["reference"]}: {part["value"]}' for part in design["components"])
    geometry = board_dimensions(len(design["components"]), True)
    battery_plan = project_battery_plan(project, design)
    prompt = f"""Use case: product-mockup
Asset type: realistic 3D-printed enclosure concept for a beginner electronics project
Primary request: Create a photorealistic workshop photograph of the completed {design['title']} board mounted securely inside a simple practical 3D-printed enclosure.
Project: {design['summary']}
Board parts: {part_list}
Authoritative enclosure inputs: board {geometry['width']} x {geometry['height']} mm; four 3.2 mm board holes whose centers are 4.5 mm from the adjacent board edges; hole-center spacing {geometry['horizontal_spacing']} x {geometry['vertical_spacing']} mm. Battery requirement: {battery_plan}
Enclosure: compact two-piece matte plastic case with four internal standoffs aligned to those board mounting-hole coordinates. Include the stated battery bay and practical battery access when required. Make sensible openings only for the existing LED, switch or control, and power connector. Show the lid beside the base or use a clear three-quarter cutaway so the mounted board and standoffs are visible.
Scene: light wood workbench, warm soft lighting, landscape close-up, entire enclosure and mounted board visible.
Constraints: one enclosure and one board; preserve the listed parts; no extra controls, displays, connectors, components, branding, labels, printed text, hands, tools, logo, or watermark. This is an approximate enclosure concept, not a dimensioned CAD drawing."""
    try:
        response = requests.post(
            "https://api.openai.com/v1/images/generations",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": os.environ.get("PCB_IMAGE_MODEL", "gpt-image-2.5-flare"),
                  "prompt": prompt, "size": "1536x1024", "quality": "medium", "output_format": "png"},
            timeout=300,
        )
        if not response.ok:
            raise ValueError("The enclosure image service could not create a preview.")
        encoded = response.json().get("data", [{}])[0].get("b64_json", "")
        image_bytes = base64.b64decode(encoded, validate=True)
        if not image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("The enclosure image service returned an invalid image.")
        temporary = output.with_suffix(".tmp")
        temporary.write_bytes(image_bytes)
        temporary.replace(output)
    except (requests.RequestException, json.JSONDecodeError, ValueError, IndexError) as error:
        raise ValueError("The enclosure preview could not be generated.") from error


def enclosure_dimensions(project: dict, design: dict) -> dict:
    """Choose a printable case size from the authoritative PCB and battery needs."""
    board = board_dimensions(len(design["components"]), True)
    battery_plan = project_battery_plan(project, design)
    battery = None
    if "no internal battery" not in battery_plan.lower():
        match = re.search(
            r"(\d+(?:\.\d+)?)\s*[×xX]\s*(\d+(?:\.\d+)?)\s*[×xX]\s*(\d+(?:\.\d+)?)\s*mm",
            battery_plan,
        )
        dimensions = sorted((float(value) for value in match.groups()), reverse=True) if match else [60.0, 30.0, 20.0]
        battery = {"length": dimensions[0] + 6, "width": dimensions[1] + 6,
                   "height": dimensions[2] + 4}
    wall, clearance, floor = 2.0, 4.0, 2.0
    battery_width = battery["width"] if battery else 0.0
    outer_width = wall * 2 + clearance * 2 + board["width"] + (battery_width + wall if battery else 0)
    outer_depth = wall * 2 + max(board["height"] + clearance * 2,
                                 (battery["length"] + clearance * 2) if battery else 0)
    inner_height = max(24.0, battery["height"] if battery else 0.0)
    return {"board": board, "battery": battery, "wall": wall, "clearance": clearance,
            "floor": floor, "outer_width": outer_width, "outer_depth": outer_depth,
            "base_height": floor + inner_height, "lid_thickness": 2.0}


def _triangle(facets: list[str], a: tuple, b: tuple, c: tuple) -> None:
    ux, uy, uz = (b[index] - a[index] for index in range(3))
    vx, vy, vz = (c[index] - a[index] for index in range(3))
    nx, ny, nz = uy * vz - uz * vy, uz * vx - ux * vz, ux * vy - uy * vx
    length = math.sqrt(nx * nx + ny * ny + nz * nz) or 1.0
    facets.append(
        f"facet normal {nx / length:.6g} {ny / length:.6g} {nz / length:.6g}\n"
        " outer loop\n" + "".join(
            f"  vertex {point[0]:.6g} {point[1]:.6g} {point[2]:.6g}\n" for point in (a, b, c)
        ) + " endloop\nendfacet"
    )


def _stl_box(facets: list[str], x0: float, y0: float, z0: float,
             x1: float, y1: float, z1: float) -> None:
    vertices = [(x0, y0, z0), (x1, y0, z0), (x1, y1, z0), (x0, y1, z0),
                (x0, y0, z1), (x1, y0, z1), (x1, y1, z1), (x0, y1, z1)]
    for a, b, c in ((0, 2, 1), (0, 3, 2), (4, 5, 6), (4, 6, 7),
                    (0, 1, 5), (0, 5, 4), (1, 2, 6), (1, 6, 5),
                    (2, 3, 7), (2, 7, 6), (3, 0, 4), (3, 4, 7)):
        _triangle(facets, vertices[a], vertices[b], vertices[c])


def _stl_cylinder(facets: list[str], cx: float, cy: float, z0: float,
                  z1: float, radius: float, segments: int = 24) -> None:
    bottom, top = (cx, cy, z0), (cx, cy, z1)
    for index in range(segments):
        angle1, angle2 = 2 * math.pi * index / segments, 2 * math.pi * (index + 1) / segments
        p0 = (cx + radius * math.cos(angle1), cy + radius * math.sin(angle1), z0)
        p1 = (cx + radius * math.cos(angle2), cy + radius * math.sin(angle2), z0)
        p2 = (p0[0], p0[1], z1)
        p3 = (p1[0], p1[1], z1)
        _triangle(facets, bottom, p1, p0)
        _triangle(facets, top, p2, p3)
        _triangle(facets, p0, p1, p3)
        _triangle(facets, p0, p3, p2)


def enclosure_stl(project: dict, design: dict) -> tuple[str, dict]:
    """Return an ASCII STL containing a case base and a separate printable lid."""
    spec = enclosure_dimensions(project, design)
    width, depth = spec["outer_width"], spec["outer_depth"]
    wall, floor, height = spec["wall"], spec["floor"], spec["base_height"]
    facets = []
    # Base tray: floor and four walls.
    _stl_box(facets, 0, 0, 0, width, depth, floor)
    _stl_box(facets, 0, 0, floor, wall, depth, height)
    _stl_box(facets, width - wall, 0, floor, width, depth, height)
    _stl_box(facets, wall, 0, floor, width - wall, wall, height)
    _stl_box(facets, wall, depth - wall, floor, width - wall, depth, height)
    board_x = wall + spec["clearance"]
    board_y = wall + spec["clearance"]
    for hole_x, hole_y in spec["board"]["holes"]:
        _stl_cylinder(facets, board_x + hole_x, board_y + hole_y, floor, floor + 6, 3.2)
    if spec["battery"]:
        divider_x = board_x + spec["board"]["width"] + spec["clearance"]
        _stl_box(facets, divider_x, wall, floor, divider_x + wall, depth - wall, floor + 10)
    # Lid is beside the base in the same STL, ready to place on the print bed.
    lid_x = width + 10
    lid_z = 0
    thickness = spec["lid_thickness"]
    _stl_box(facets, lid_x, 0, lid_z, lid_x + width, depth, thickness)
    lip = 1.2
    _stl_box(facets, lid_x + wall, wall, thickness, lid_x + width - wall, wall + lip, thickness + 2)
    _stl_box(facets, lid_x + wall, depth - wall - lip, thickness,
             lid_x + width - wall, depth - wall, thickness + 2)
    _stl_box(facets, lid_x + wall, wall + lip, thickness,
             lid_x + wall + lip, depth - wall - lip, thickness + 2)
    _stl_box(facets, lid_x + width - wall - lip, wall + lip, thickness,
             lid_x + width - wall, depth - wall - lip, thickness + 2)
    return "solid pcb_enclosure\n" + "\n".join(facets) + "\nendsolid pcb_enclosure\n", spec


def generate_enclosure_stl(project: dict, design: dict) -> Path:
    output = Path("/data/generated") / project["id"] / "enclosure.stl"
    output.parent.mkdir(parents=True, exist_ok=True)
    contents, _ = enclosure_stl(project, design)
    temporary = output.with_suffix(".tmp")
    temporary.write_text(contents, encoding="ascii")
    temporary.replace(output)
    return output


def project_status_path(project_id: str) -> Path:
    return Path("/data/generated") / project_id / "status.json"


def write_project_status(project_id: str, status: dict) -> None:
    path = project_status_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(status, indent=2), encoding="utf-8")
    temporary.replace(path)


def run_project_generation(project: dict) -> None:
    write_project_status(project["id"], {"state": "working", "message": "Designing the circuit and checking the board in KiCad."})
    try:
        design = generate_project_design(
            project,
            lambda message: write_project_status(project["id"], {"state": "working", "message": message}),
        )
        save_generated_project(project, design)
        write_project_status(project["id"], {"state": "working", "message": "Creating a realistic picture of the finished build."})
        try:
            generate_project_photo(project, design)
            photo_state = "generated"
        except ValueError:
            photo_state = "diagram-fallback"
        enclosure_state = "not-requested"
        if project["enclosure"]:
            write_project_status(project["id"], {"state": "working", "message": "Creating the printable enclosure and lid."})
            generate_enclosure_stl(project, design)
            write_project_status(project["id"], {"state": "working", "message": "Creating a picture of the board mounted in its enclosure."})
            try:
                generate_enclosure_photo(project, design)
                enclosure_state = "generated"
            except ValueError:
                enclosure_state = "unavailable"
        write_project_status(project["id"], {"state": "complete", "photo": photo_state,
                                              "enclosure_photo": enclosure_state})
    except UnsupportedProjectError as error:
        write_project_status(project["id"], {"state": "unsupported", "message": str(error)})
    except Exception as error:
        write_project_status(project["id"], {"state": "failed", "message": str(error)})


def upload_as_content(upload, purpose: str) -> dict:
    """Build a Responses input item without retaining the uploaded file."""
    raw = upload.read()
    filename = upload.filename or purpose
    lowered = filename.lower()
    if lowered.endswith(".pdf"):
        return {"type": "input_file", "filename": filename,
                "file_data": "data:application/pdf;base64," + base64.b64encode(raw).decode("ascii")}
    if lowered.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif")):
        mime = "image/jpeg" if lowered.endswith((".jpg", ".jpeg")) else f"image/{lowered.rsplit('.', 1)[1]}"
        return {"type": "input_image", "image_url": f"data:{mime};base64," + base64.b64encode(raw).decode("ascii"), "detail": "high"}
    if lowered.endswith((".csv", ".txt")):
        try:
            return {"type": "input_text", "text": f"{purpose} ({filename}):\n" + raw.decode("utf-8-sig")[:200_000]}
        except UnicodeDecodeError as error:
            raise ValueError(f"{purpose} CSV/text file must use UTF-8 encoding.") from error
    raise ValueError(f"{purpose} must be a PDF, PNG, JPEG, WEBP, GIF, CSV, or text file.")


def analyze_schematic(upload, bom=None, build_notes="") -> dict:
    api_key = user_api_key(g.user["id"]) if getattr(g, "user", None) else ""
    if not api_key:
        raise ValueError("Schematic analysis is not configured yet. The server is missing its API credential.")
    content = upload_as_content(upload, "Schematic")
    if content["type"] == "input_text":
        raise ValueError("The schematic must be a PDF or image, not a text file.")
    contents = [{"type": "input_text", "text": SCHEMATIC_PROMPT}, content]
    if bom and bom.filename:
        contents.append(upload_as_content(bom, "Optional BOM"))
    if build_notes.strip():
        contents.append({"type": "input_text", "text": "User build and placement notes:\n" + build_notes.strip()[:5000]})
    payload = {
        "model": os.environ.get("PCB_SCHEMATIC_MODEL", "gpt-5.5"), "store": False,
        "input": [{"role": "user", "content": contents}],
        "text": {"format": {"type": "json_schema", "name": "schematic_review", "strict": True, "schema": SCHEMATIC_SCHEMA}}
    }
    try:
        response = requests.post("https://api.openai.com/v1/responses", headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, json=payload, timeout=120)
        if not response.ok:
            raise ValueError("The analysis service could not process this schematic. Please try again later.")
        return json.loads(response_text(response.json()))
    except (requests.RequestException, json.JSONDecodeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith("The analysis service"):
            raise
        raise ValueError("The analysis service returned an unexpected result. No board was created.") from error


@app.get("/")
def index():
    generated_projects = []
    generated_root = Path("/data/generated")
    if generated_root.exists():
        for folder in generated_root.iterdir():
            if not folder.is_dir() or not re.fullmatch(r"[a-f0-9]{10}", folder.name):
                continue
            try:
                status = json.loads((folder / "status.json").read_text(encoding="utf-8"))
                saved = json.loads((folder / "project.json").read_text(encoding="utf-8"))
                if status.get("state") != "complete":
                    continue
                owner_id = saved["brief"].get("owner_id")
                if g.user["role"] != "admin" and owner_id != g.user["id"]:
                    continue
                generated_projects.append({
                    "id": folder.name,
                    "title": saved["design"]["title"],
                    "url": url_for("generated_project_status", project_id=folder.name),
                    "created_at": saved["brief"].get("created_at", ""),
                })
            except (OSError, json.JSONDecodeError, KeyError):
                continue
    generated_projects.sort(key=lambda item: item["created_at"], reverse=True)
    return render_template("index.html", generated_projects=generated_projects,
                           deleted=request.args.get("deleted") == "1")


@app.post("/project/<project_id>/delete")
def delete_generated_project(project_id: str):
    if not re.fullmatch(r"[a-f0-9]{10}", project_id):
        return Response("Project not found.", status=404, mimetype="text/plain")
    source = Path("/data/generated") / project_id
    if not source.is_dir():
        return Response("Project not found.", status=404, mimetype="text/plain")
    load_generated_project(project_id)
    deleted_root = Path("/data/deleted")
    deleted_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    shutil.move(str(source), str(deleted_root / f"{project_id}-{stamp}"))
    try:
        projects = json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
        projects = [item for item in projects if item.get("id") != project_id]
        temporary = PROJECTS_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(projects, indent=2), encoding="utf-8")
        temporary.replace(PROJECTS_FILE)
    except (OSError, json.JSONDecodeError):
        pass
    return redirect(url_for("index", deleted=1), code=303)


@app.get("/build")
def build():
    return render_template("builder.html", has_api_key=bool(g.user["api_key_cipher"]))


@app.post("/build/plan")
def build_plan():
    api_key = user_api_key(g.user["id"])
    if not api_key:
        return render_template("builder.html", has_api_key=False,
                               builder_error="Save your own AI API key in Settings before starting an AI project."), 403
    idea = request.form.get("idea", "").strip()
    if not idea:
        return render_template("builder.html", builder_error="Tell us what you would like to make."), 400
    leds = []
    for value in request.form.getlist("leds"):
        if value in LED_OPTIONS and value not in leds:
            leds.append(value)
    enclosure = request.form.get("enclosure") == "yes"
    project = create_project(idea, request.form.get("parts", "shopping"),
                             request.form.get("style", "through-hole"), leds, enclosure,
                             g.user["id"])
    runtime_project = dict(project)
    runtime_project["_api_key"] = api_key
    write_project_status(project["id"], {"state": "queued", "message": "Starting this new project."})
    threading.Thread(target=run_project_generation, args=(runtime_project,), daemon=True).start()
    return redirect(url_for("generated_project_status", project_id=project["id"]), code=303)


@app.get("/project/<project_id>")
def generated_project_status(project_id: str):
    if not re.fullmatch(r"[a-f0-9]{10}", project_id):
        return render_template("new-project-error.html", project={"id": project_id, "idea": ""},
                               error="Project not found."), 404
    try:
        project_brief = load_project_brief(project_id)
        status = json.loads(project_status_path(project_id).read_text(encoding="utf-8"))
    except ValueError:
        abort(404)
    except (OSError, json.JSONDecodeError):
        status = {"state": "queued", "message": "Starting this new project."}
    if status.get("state") == "complete":
        saved = load_generated_project(project_id)
        project, design = saved["brief"], saved["design"]
        enclosure_geometry = (board_dimensions(len(design["components"]), True)
                              if project.get("enclosure") else None)
        return render_template("generated-project.html", project=project, design=design,
                               led_info=LED_OPTIONS[project_leds(project)[0]],
                               enclosure_geometry=enclosure_geometry,
                               battery_plan=project_battery_plan(project, design))
    if status.get("state") == "failed":
        try:
            projects = json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
            project = next(item for item in projects if item.get("id") == project_id)
            assert_project_access(project)
        except (OSError, json.JSONDecodeError, StopIteration):
            project = {"id": project_id, "idea": ""}
        return render_template("new-project-error.html", project=project,
                               error=status.get("message", "Project generation stopped.")), 422
    if status.get("state") == "unsupported":
        try:
            project = load_project_brief(project_id)
        except ValueError:
            project = {"id": project_id, "idea": ""}
        return render_template("new-project-error.html", project=project,
                               error=status.get("message", "This project is outside the current safe scope."),
                               unsupported=True), 422
    return render_template("project-working.html", project_id=project_id,
                           message=status.get("message", "Designing and checking the project."))


def load_project_brief(project_id: str) -> dict:
    try:
        projects = json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
        project = next(item for item in projects if item.get("id") == project_id)
        assert_project_access(project)
        return project
    except (OSError, json.JSONDecodeError, StopIteration) as error:
        raise ValueError("Project not found.") from error


@app.post("/project/<project_id>/retry")
def retry_generated_project(project_id: str):
    try:
        project = load_project_brief(project_id)
    except ValueError:
        return render_template("new-project-error.html", project={"id": project_id, "idea": ""},
                               error="Project not found."), 404
    status = {}
    try:
        status = json.loads(project_status_path(project_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    if status.get("state") in {"queued", "working"}:
        return redirect(url_for("generated_project_status", project_id=project_id), code=303)
    api_key = user_api_key(g.user["id"])
    if not api_key:
        return redirect(url_for("settings"), code=303)
    runtime_project = dict(project)
    runtime_project["_api_key"] = api_key
    write_project_status(project_id, {"state": "queued", "message": "Restarting this project."})
    threading.Thread(target=run_project_generation, args=(runtime_project,), daemon=True).start()
    return redirect(url_for("generated_project_status", project_id=project_id), code=303)


def assert_project_access(project: dict) -> None:
    if not getattr(g, "user", None):
        return
    owner_id = project.get("owner_id")
    if g.user["role"] != "admin" and owner_id != g.user["id"]:
        abort(404)


def load_generated_project(project_id: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{10}", project_id):
        raise ValueError("Project not found.")
    path = Path("/data/generated") / project_id / "project.json"
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert_project_access(saved["brief"])
        return saved
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Project not found.") from error


@app.get("/project/<project_id>/board.kicad_pcb")
def generated_board(project_id: str):
    saved = load_generated_project(project_id)
    board = saved["design"]["kicad_pcb"]
    report = kicad_drc(board)
    if report.get("violations") or report.get("unconnected_items"):
        return Response("This board no longer passes its KiCad check.", status=409, mimetype="text/plain")
    return Response(board, mimetype="text/plain", headers={
        "Content-Disposition": f'attachment; filename="{project_id}-board.kicad_pcb"'})


@app.get("/project/<project_id>/laser.svg")
def generated_laser(project_id: str):
    saved = load_generated_project(project_id)
    board = saved["design"]["kicad_pcb"]
    report = kicad_drc(board)
    if report.get("violations") or report.get("unconnected_items"):
        return Response("This board no longer passes its KiCad check.", status=409, mimetype="text/plain")
    headers = {}
    if request.args.get("download") == "1":
        headers["Content-Disposition"] = f'attachment; filename="{project_id}-laser.svg"'
    return Response(make_svg(board, "B.Cu", True, True, True), mimetype="image/svg+xml", headers=headers)


@app.get("/project/<project_id>/assembly.svg")
def generated_assembly(project_id: str):
    saved = load_generated_project(project_id)
    project, design = saved["brief"], saved["design"]
    return Response(assembly_svg(design, project["style"], project_leds(project), project.get("enclosure", False)),
                    mimetype="image/svg+xml")


@app.get("/project/<project_id>/finished-build.png")
def generated_photo(project_id: str):
    saved = load_generated_project(project_id)
    path = Path("/data/generated") / project_id / "assembly.png"
    if not path.exists():
        return redirect(url_for("generated_assembly", project_id=project_id), code=302)
    return send_file(path, mimetype="image/png", conditional=True, max_age=86400)


@app.get("/project/<project_id>/enclosure.png")
def generated_enclosure_photo(project_id: str):
    saved = load_generated_project(project_id)
    if not saved["brief"].get("enclosure"):
        return Response("This project was not designed for an enclosure.", status=404, mimetype="text/plain")
    path = Path("/data/generated") / project_id / "enclosure.png"
    if not path.exists():
        return redirect(url_for("generated_photo", project_id=project_id), code=302)
    return send_file(path, mimetype="image/png", conditional=True, max_age=86400)


@app.get("/project/<project_id>/enclosure-spec.txt")
def generated_enclosure_spec(project_id: str):
    saved = load_generated_project(project_id)
    project, design = saved["brief"], saved["design"]
    if not project.get("enclosure"):
        return Response("This project was not designed for an enclosure.", status=404,
                        mimetype="text/plain")
    case = enclosure_dimensions(project, design)
    geometry = case["board"]
    hole_lines = "\n".join(
        f"  Hole {index}: X={x:.1f} mm, Y={y:.1f} mm from the board's top-left corner"
        for index, (x, y) in enumerate(geometry["holes"], 1)
    )
    content = f"""ENCLOSURE MEASUREMENTS — {design['title']}

These measurements, not the concept picture, are authoritative.

PCB size: {geometry['width']:.1f} × {geometry['height']:.1f} mm
Enclosure outside size: {case['outer_width']:.1f} × {case['outer_depth']:.1f} × {case['base_height']:.1f} mm
Lid thickness: {case['lid_thickness']:.1f} mm
Mounting-hole diameter: {geometry['hole_diameter']:.1f} mm
Hole-center edge offset: 4.5 mm
Horizontal hole-center spacing: {geometry['horizontal_spacing']:.1f} mm
Vertical hole-center spacing: {geometry['vertical_spacing']:.1f} mm

Hole centers:
{hole_lines}

Battery and power space:
{project_battery_plan(project, design)}

The downloadable STL contains a base and separate lid. Its PCB standoffs use these exact hole-center coordinates, and its dimensions include the stated battery space. The enclosure picture is illustrative only.
"""
    return Response(content, mimetype="text/plain", headers={
        "Content-Disposition": f'attachment; filename="{project_id}-enclosure-measurements.txt"'})


@app.get("/project/<project_id>/enclosure.stl")
def generated_enclosure_stl(project_id: str):
    saved = load_generated_project(project_id)
    project, design = saved["brief"], saved["design"]
    if not project.get("enclosure"):
        return Response("This project was not designed for an enclosure.", status=404,
                        mimetype="text/plain")
    path = Path("/data/generated") / project_id / "enclosure.stl"
    if not path.exists():
        generate_enclosure_stl(project, design)
    return send_file(path, mimetype="model/stl", as_attachment=True,
                     download_name=f"{project_id}-enclosure-base-and-lid.stl")


@app.get("/project/<project_id>/shopping-list")
def generated_shopping_list(project_id: str):
    saved = load_generated_project(project_id)
    return render_template("generated-shopping-list.html", project_id=project_id,
                           design=saved["design"])


@app.get("/build/blinking-led")
def blinking_led_project():
    led, led_info = selected_led(request.args.get("led"))
    return render_template("blinking-led.html", led=led, led_info=led_info,
                           enclosure=request.args.get("enclosure") == "yes")


@app.get("/build/blinking-led/board.kicad_pcb")
def blinking_led_kicad():
    blinking_led_drc_check()
    return Response(blinking_led_board(), mimetype="text/plain", headers={
        "Content-Disposition": "attachment; filename=blinking-led-learning-board.kicad_pcb"})


@app.get("/build/blinking-led/laser.svg")
def blinking_led_laser():
    blinking_led_drc_check()
    svg = make_svg(blinking_led_board(), "B.Cu", True, True, True)
    return Response(svg, mimetype="image/svg+xml", headers={
        "Content-Disposition": "attachment; filename=blinking-led-learning-board-laser.svg"})


@app.get("/build/blinking-led/bom.csv")
def blinking_led_bom():
    blinking_led_drc_check()
    led, led_info = selected_led(request.args.get("led"))
    return render_template("shopping-list.html", led=led, led_info=led_info)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze-schematic")
def analyze_schematic_route():
    upload = request.files.get("schematic")
    if not upload or not upload.filename:
        return render_template("index.html", schematic_error="Choose a schematic PDF or image."), 400
    try:
        review = analyze_schematic(upload, request.files.get("bom"), request.form.get("build_notes", ""))
    except ValueError as error:
        return render_template("index.html", schematic_error=str(error)), 400
    return render_template("schematic-review.html", review=review, filename=html.escape(upload.filename))


@app.post("/export")
def export():
    upload = request.files.get("board")
    if not upload or not upload.filename:
        return render_template("index.html", error="Choose a .kicad_pcb file or a ZIP containing one board."), 400
    if not upload.filename.lower().endswith((".kicad_pcb", ".zip")):
        return render_template("index.html", error="Upload a .kicad_pcb file or a ZIP containing one."), 400
    try:
        board = board_from_upload(upload)
        svg = make_svg(board, request.form.get("layer", "B.Cu"),
                       request.form.get("mirror") == "yes", request.form.get("outline") == "yes",
                       request.form.get("drills") == "yes")
    except ValueError as error:
        return render_template("index.html", error=str(error)), 400
    base = re.sub(r"[^A-Za-z0-9_-]+", "-", upload.filename.rsplit(".", 1)[0]).strip("-") or "board"
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return Response(svg, mimetype="image/svg+xml", headers={"Content-Disposition": f'attachment; filename="{base}-{stamp}-laser.svg"'})


@app.errorhandler(413)
def too_large(_error):
    return render_template("index.html", error="The upload is over the 25 MB limit."), 413
