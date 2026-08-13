#!/usr/bin/env python3
"""
Hospital Laboratory Management System
Backend : Flask
Storage : CSV files (data/*.csv)

Security features:
  - Session-based authentication (users.csv, hashed passwords)
  - CSRF token validation on all state-changing requests
  - Login brute-force lockout
  - Security headers (CSP, nosniff, frame options)
  - CSV formula-injection sanitisation
  - Input validation and XSS-safe output
  - Enforced password change for default credentials
"""
import csv
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (Flask, render_template, request, redirect, url_for,
                   jsonify, flash, session, abort)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

app = Flask(__name__)

# ------------------------------------------------------------------
# Configuration (secret key persisted so sessions survive restarts)
# ------------------------------------------------------------------
def _load_secret_key():
    env_key = os.environ.get("LAB_SECRET_KEY", "").strip()
    if env_key:
        return env_key
    key_file = os.path.join(DATA_DIR, ".secret_key")
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(key_file):
        with open(key_file, "r", encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    with open(key_file, "w", encoding="utf-8") as f:
        f.write(key)
    os.chmod(key_file, 0o600)
    return key


app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("LAB_SSL", "").strip() == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

CSV_FILES = {
    "users":        ["id", "username", "full_name", "role", "password_hash", "must_change", "created_at"],
    "patients":     ["id", "name", "age", "gender", "phone", "email", "doctor", "created_at"],
    "tests":        ["id", "test_name", "category", "price", "turnaround_hours", "reference_range", "unit"],
    "profiles":     ["id", "profile_name", "description", "created_at"],
    "profile_tests":["profile_id", "test_id"],
    "orders":       ["id", "patient_id", "priority", "status", "requested_by", "ordered_at"],
    "order_tests":  ["id", "order_id", "test_id", "price", "status", "result_value", "unit", "reference_range", "entered_at"],
}

LINE_STATUSES = ["Pending", "Collected", "In Progress", "Completed", "Cancelled"]
ROLES = ["admin", "staff"]

LOCKOUT_ATTEMPTS = 5
LOCKOUT_SECONDS = 900
LOGIN_FAILURES = defaultdict(list)

_MAX_TEXT = 200


# ------------------------- CSV helpers -------------------------
def _file_path(name):
    return os.path.join(DATA_DIR, f"{name}.csv")


def _sanitize_cell(value):
    """Prevent CSV formula injection (=, +, -, @) when file is opened in Excel."""
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    dangerous = (
        stripped.startswith(("=", "+", "@"))
        or (stripped.startswith("-") and not re.match(r"^-?\d+(\.\d+)?$", stripped))
    )
    return "'" + value if dangerous else value


def _unsanitize_cell(value):
    if isinstance(value, str) and len(value) > 1 and value[0] == "'" and value[1] in "=+-@":
        return value[1:]
    return value


def ensure_data_files():
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass
    for name, fields in CSV_FILES.items():
        path = _file_path(name)
        if not os.path.exists(path):
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
        try:
            os.chmod(path, 0o600 if name == "users" else 0o644)
        except OSError:
            pass


def read_csv(name):
    path = _file_path(name)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        for k in row:
            row[k] = _unsanitize_cell(row[k])
    return rows


def write_csv(name, rows):
    fields = CSV_FILES[name]
    path = _file_path(name)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _sanitize_cell(row.get(k, "")) for k in fields})
    try:
        os.chmod(path, 0o600 if name == "users" else 0o644)
    except OSError:
        pass


def get_record(name, record_id):
    for row in read_csv(name):
        if row.get("id") == record_id:
            return row
    return None


def next_id(name, prefix):
    rows = read_csv(name)
    nums = []
    for r in rows:
        m = re.match(rf"^{prefix}(\d+)$", r.get("id", ""))
        if m:
            nums.append(int(m.group(1)))
    return f"{prefix}{max(nums) + 1 if nums else 1:04d}"


def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today():
    return datetime.now().strftime("%Y-%m-%d")


# ------------------------- domain helpers -------------------------
def map_by_id(name):
    return {r["id"]: r for r in read_csv(name)}


def patient_map():
    return {r["id"]: r["name"] for r in read_csv("patients")}


def test_map():
    return {r["id"]: r for r in read_csv("tests")}


def profile_summary():
    """profile id -> (info, [test_ids]) with computed total price."""
    profiles = read_csv("profiles")
    links = read_csv("profile_tests")
    tests = test_map()
    out = {}
    for p in profiles:
        member_ids = [l["test_id"] for l in links if l["profile_id"] == p["id"] and l["test_id"] in tests]
        total = sum(float(tests[t].get("price", 0) or 0) for t in member_ids)
        out[p["id"]] = {"profile": p, "test_ids": member_ids, "count": len(member_ids), "total": total}
    return out


def expand_selection(profile_ids, test_ids):
    """Turn a mix of profile ids + individual test ids into a unique test id list."""
    tests = test_map()
    links = read_csv("profile_tests")
    selected = set()
    for pid in profile_ids:
        for l in links:
            if l["profile_id"] == pid and l["test_id"] in tests:
                selected.add(l["test_id"])
    for t in test_ids:
        if t in tests:
            selected.add(t)
    return sorted(selected, key=lambda x: x)


def item_price(test_id):
    t = test_map().get(test_id)
    return float(t["price"]) if t and t.get("price") else 0.0


def derive_order_status(items):
    if not items:
        return "Pending"
    statuses = {i.get("status", "Pending") for i in items}
    if len(statuses) == 1:
        return next(iter(statuses))
    if "Completed" in statuses or "Collected" in statuses or "In Progress" in statuses:
        return "In Progress"
    return "Pending"


def refresh_order_status(order_id):
    items = [i for i in read_csv("order_tests") if i["order_id"] == order_id]
    status = derive_order_status(items)
    orders = read_csv("orders")
    for o in orders:
        if o["id"] == order_id:
            o["status"] = status
            write_csv("orders", orders)
            break
    return status


def order_total(order_id):
    items = [i for i in read_csv("order_tests") if i["order_id"] == order_id]
    return sum(float(i.get("price", 0) or 0) for i in items if i.get("status") != "Cancelled")


def enrich_order(o):
    """Attach patient name and total to an order dict."""
    o = dict(o)
    pm = patient_map()
    o["patient_name"] = pm.get(o.get("patient_id", ""), o.get("patient_id", ""))
    o["total"] = order_total(o["id"])
    return o


def tests_by_category():
    cats = {}
    for t in sorted(read_csv("tests"), key=lambda x: x["test_name"].lower()):
        cats.setdefault(t["category"] or "General", []).append(t)
    return cats


# ------------------------- input helpers -------------------------
def clean_text(value, maxlen=_MAX_TEXT):
    """Trim, collapse whitespace and cap length of free-text input."""
    if value is None:
        return ""
    return " ".join(str(value).strip().split())[:maxlen]


def safe_id(value):
    """Only allow safe identifier strings (avoid CSV/path tampering)."""
    if not value or not re.match(r"^[A-Za-z0-9_-]{1,20}$", value):
        return ""
    return value


# ------------------------- authentication -------------------------
def current_user():
    uid = session.get("user_id", "")
    if not uid:
        return None
    return get_record("users", uid)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue", "error")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login", next=request.path))
        if user.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ------------------------- CSRF -------------------------
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def is_safe_redirect(target):
    return target.startswith("/") and not target.startswith("//")


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        provided = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, provided):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "CSRF token missing or invalid"}), 403
            abort(403)


# ------------------------- brute-force lockout -------------------------
def _lock_key(username):
    return f"{username.lower()}|{request.remote_addr or '0.0.0.0'}"


def is_locked_out(username):
    now = time.time()
    fails = [t for t in LOGIN_FAILURES[_lock_key(username)] if now - t < LOCKOUT_SECONDS]
    LOGIN_FAILURES[_lock_key(username)] = fails
    if len(fails) >= LOCKOUT_ATTEMPTS:
        return max(1, int(LOCKOUT_SECONDS - (now - fails[-1])))
    return 0


def record_failure(username):
    key = _lock_key(username)
    LOGIN_FAILURES[key].append(time.time())
    LOGIN_FAILURES[key] = [t for t in LOGIN_FAILURES[key] if time.time() - t < LOCKOUT_SECONDS]


def clear_failures(username):
    LOGIN_FAILURES.pop(_lock_key(username), None)


# ------------------------- login / logout -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = clean_text(request.form.get("username", ""))
        password = request.form.get("password", "")
        if not username or not password:
            flash("Enter username and password", "error")
            return redirect(url_for("login"))

        remaining = is_locked_out(username)
        if remaining:
            flash(f"Too many failed attempts. Account locked for {remaining // 60} minute(s).", "error")
            return render_template("login.html")

        user = next((u for u in read_csv("users") if u["username"].lower() == username.lower()), None)
        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            clear_failures(username)
            if user.get("must_change") == "1":
                flash("You must change your password before continuing", "warning")
                return redirect(url_for("change_password"))
            nxt = request.args.get("next", "")
            if is_safe_redirect(nxt):
                return redirect(nxt)
            return redirect(url_for("dashboard"))

        record_failure(username)
        flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("login"))


# ------------------------- password management -------------------------
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not check_password_hash(user["password_hash"], current_pw):
            flash("Current password is incorrect", "error")
        elif len(new_pw) < 8:
            flash("New password must be at least 8 characters", "error")
        elif new_pw != confirm:
            flash("Passwords do not match", "error")
        else:
            users = read_csv("users")
            for u in users:
                if u["id"] == user["id"]:
                    u["password_hash"] = generate_password_hash(new_pw)
                    u["must_change"] = "0"
            write_csv("users", users)
            session["must_change_ok"] = True
            flash("Password changed successfully", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", user=user)


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users_page():
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "create":
            username = clean_text(request.form.get("username", ""), 32)
            full_name = clean_text(request.form.get("full_name", ""))
            role = request.form.get("role", "staff")
            password = request.form.get("password", "")
            if not re.match(r"^[a-zA-Z0-9_.-]{3,32}$", username):
                flash("Username must be 3-32 characters (letters, digits, _ . -)", "error")
            elif role not in ROLES:
                flash("Invalid role", "error")
            elif len(password) < 8:
                flash("Password must be at least 8 characters", "error")
            elif any(u["username"].lower() == username.lower() for u in read_csv("users")):
                flash("Username already exists", "error")
            else:
                rows = read_csv("users")
                rows.append({
                    "id": next_id("users", "USR"), "username": username,
                    "full_name": full_name, "role": role,
                    "password_hash": generate_password_hash(password),
                    "must_change": "0", "created_at": now_ts(),
                })
                write_csv("users", rows)
                flash(f"User {username} created", "success")
        elif action == "delete":
            uid = request.form.get("user_id", "")
            if uid == session["user_id"]:
                flash("You cannot delete your own account", "error")
            else:
                write_csv("users", [u for u in read_csv("users") if u["id"] != uid])
                flash("User deleted", "success")
        elif action == "reset":
            uid = request.form.get("user_id", "")
            password = request.form.get("password", "")
            if len(password) < 8:
                flash("Password must be at least 8 characters", "error")
            else:
                rows = read_csv("users")
                for u in rows:
                    if u["id"] == uid:
                        u["password_hash"] = generate_password_hash(password)
                        u["must_change"] = "1"
                write_csv("users", rows)
                flash("Password reset; user must change it on next login", "success")
        return redirect(url_for("users_page"))
    return render_template("users.html", users=read_csv("users"))


# ------------------------- global enforcement -------------------------
@app.before_request
def enforce_auth():
    if request.endpoint in ("login", "static") or request.endpoint is None:
        return
    if not session.get("user_id"):
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Authentication required"}), 401
        return redirect(url_for("login", next=request.path))
    # force password change for accounts still on default / reset credentials
    user = get_record("users", session.get("user_id", ""))
    if user and user.get("must_change") == "1" and request.endpoint not in ("change_password", "logout"):
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Password change required"}), 403
        flash("You must change your password before continuing", "warning")
        return redirect(url_for("change_password"))


# ------------------------- security headers -------------------------
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return resp


# ------------------------- error handlers -------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access denied"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found"), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413, message="Upload too large"), 413


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Internal server error"), 500


# ------------------------- context -------------------------
@app.context_processor
def inject_globals():
    user = current_user()
    return {
        "all_statuses": LINE_STATUSES,
        "today_str": today(),
        "csrf_token": get_csrf_token,
        "current_user": user,
    }


# ------------------------- Dashboard -------------------------
@app.route("/")
def dashboard():
    patients = read_csv("patients")
    tests = read_csv("tests")
    orders = [enrich_order(o) for o in read_csv("orders")]
    items = read_csv("order_tests")
    profiles = read_csv("profiles")

    order_status = Counter(o.get("status", "Pending") for o in orders)
    cat_counter = Counter(t.get("category", "General") for t in tests)
    completed = [i for i in items if i.get("status") == "Completed"]
    revenue = sum(float(i.get("price", 0) or 0) for i in completed)

    recent = sorted(orders, key=lambda o: o.get("ordered_at", ""), reverse=True)[:6]
    t_map = test_map()

    return render_template(
        "dashboard.html",
        active="dashboard",
        stats={
            "patients": len(patients),
            "tests": len(tests),
            "profiles": len(profiles),
            "orders": len(orders),
            "pending": sum(1 for o in orders if o["status"] in ("Pending", "In Progress")),
            "completed": order_status.get("Completed", 0),
            "revenue": revenue,
        },
        categories=cat_counter,
        recent_orders=recent,
        t_map=t_map,
    )


@app.route("/api/dashboard")
def api_dashboard():
    orders = read_csv("orders")
    return jsonify({"ok": True, "status_counts": dict(Counter(o.get("status", "Pending") for o in orders))})


# ------------------------- Patients -------------------------
@app.route("/patients", methods=["GET", "POST"])
def patients_page():
    if request.method == "POST":
        name = clean_text(request.form.get("name", ""))
        age = clean_text(request.form.get("age", ""), 3)
        if not name:
            flash("Patient name is required", "error")
        elif age and not age.isdigit():
            flash("Age must be a number", "error")
        else:
            rows = read_csv("patients")
            new_id = next_id("patients", "PAT")
            rows.append({
                "id": new_id, "name": name, "age": age,
                "gender": clean_text(request.form.get("gender", ""), 16),
                "phone": clean_text(request.form.get("phone", ""), 20),
                "email": clean_text(request.form.get("email", ""), 100),
                "doctor": clean_text(request.form.get("doctor", "")),
                "created_at": now_ts(),
            })
            write_csv("patients", rows)
            flash(f"Patient {new_id} registered successfully", "success")
            return redirect(url_for("patients_page"))
    return render_template("patients.html", active="patients", patients=read_csv("patients"))


# ------------------------- Test Catalog -------------------------
@app.route("/tests", methods=["GET", "POST"])
def tests_page():
    if request.method == "POST":
        test_name = clean_text(request.form.get("test_name", ""))
        price = clean_text(request.form.get("price", ""), 12)
        if not test_name:
            flash("Test name is required", "error")
        elif price and not re.match(r"^\d+(\.\d{1,2})?$", price):
            flash("Price must be a valid amount", "error")
        else:
            rows = read_csv("tests")
            new_id = next_id("tests", "TST")
            rows.append({
                "id": new_id, "test_name": test_name,
                "category": clean_text(request.form.get("category", ""), 40) or "General",
                "price": price or "0",
                "turnaround_hours": clean_text(request.form.get("turnaround_hours", ""), 6) or "24",
                "reference_range": clean_text(request.form.get("reference_range", "")),
                "unit": clean_text(request.form.get("unit", ""), 20),
            })
            write_csv("tests", rows)
            flash(f"Test {test_name} added to catalog", "success")
            return redirect(url_for("tests_page"))
    return render_template("tests.html", active="tests", tests=read_csv("tests"))


# ------------------------- Profiles -------------------------
def save_profile(profile_id=None):
    name = request.form.get("profile_name", "").strip()
    description = request.form.get("description", "").strip()
    selected = request.form.getlist("test_ids")
    if not name:
        flash("Profile name is required", "error")
        return None
    if not selected:
        flash("Select at least one test for the profile", "error")
        return None
    tests = test_map()
    selected = [t for t in selected if t in tests]
    if not selected:
        flash("Selected tests are invalid", "error")
        return None

    profiles = read_csv("profiles")
    if profile_id:
        profile = get_record("profiles", profile_id)
        if not profile:
            flash("Profile not found", "error")
            return None
        for p in profiles:
            if p["id"] == profile_id:
                p["profile_name"] = name
                p["description"] = description
    else:
        profile_id = next_id("profiles", "PRF")
        profiles.append({
            "id": profile_id, "profile_name": name,
            "description": description, "created_at": now_ts(),
        })
    write_csv("profiles", profiles)

    links = [l for l in read_csv("profile_tests") if l["profile_id"] != profile_id]
    for t in selected:
        links.append({"profile_id": profile_id, "test_id": t})
    write_csv("profile_tests", links)
    return profile_id


@app.route("/profiles", methods=["GET", "POST"])
def profiles_page():
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "delete":
            pid = request.form.get("profile_id", "")
            write_csv("profiles", [p for p in read_csv("profiles") if p["id"] != pid])
            write_csv("profile_tests", [l for l in read_csv("profile_tests") if l["profile_id"] != pid])
            flash("Profile deleted", "success")
            return redirect(url_for("profiles_page"))
        profile_id = save_profile(request.form.get("profile_id") or None)
        if profile_id:
            flash(f"Profile {profile_id} saved", "success")
            return redirect(url_for("profiles_page"))
    summaries = profile_summary()
    t_map = test_map()
    return render_template(
        "profiles.html", active="profiles",
        profiles=summaries, tests_by_cat=tests_by_category(),
        t_map=t_map,
    )


# ------------------------- Test Orders -------------------------
@app.route("/orders", methods=["GET", "POST"])
def orders_page():
    if request.method == "POST":
        patient_id = safe_id(request.form.get("patient_id", ""))
        priority = request.form.get("priority", "Routine").strip() or "Routine"
        requested_by = clean_text(request.form.get("requested_by", "")) or "Reception"
        selected = expand_selection(request.form.getlist("profile_ids"), request.form.getlist("test_ids"))

        if priority not in ("Routine", "Urgent", "Stat"):
            flash("Invalid priority", "error")
        elif not patient_id:
            flash("Select a patient", "error")
        elif patient_id not in patient_map():
            flash("Invalid patient selected", "error")
        elif not selected:
            flash("Select at least one test or profile", "error")
        else:
            order_id = next_id("orders", "ORD")
            orders = read_csv("orders")
            orders.append({
                "id": order_id, "patient_id": patient_id, "priority": priority,
                "status": "Pending", "requested_by": requested_by, "ordered_at": now_ts(),
            })
            write_csv("orders", orders)
            add_items_to_order(order_id, selected)
            refresh_order_status(order_id)
            flash(f"Order {order_id} created with {len(selected)} test(s)", "success")
            return redirect(url_for("order_detail", order_id=order_id))

    orders = [enrich_order(o) for o in read_csv("orders")]
    orders.sort(key=lambda o: o.get("ordered_at", ""), reverse=True)
    return render_template(
        "orders.html", active="orders", orders=orders,
        patients=read_csv("patients"),
        tests_by_cat=tests_by_category(), profiles=read_csv("profiles"),
        profile_summaries=profile_summary(),
    )


def add_items_to_order(order_id, test_ids):
    existing = {i["test_id"] for i in read_csv("order_tests") if i["order_id"] == order_id}
    items = read_csv("order_tests")
    nums = [int(m.group(1)) for r in items if (m := re.match(r"^ITM(\d+)$", r.get("id", "")))]
    counter = max(nums) if nums else 0
    for t in test_ids:
        if t in existing:
            continue
        existing.add(t)
        counter += 1
        items.append({
            "id": f"ITM{counter:04d}",
            "order_id": order_id, "test_id": t,
            "price": str(item_price(t)), "status": "Pending",
            "result_value": "", "unit": "", "reference_range": "", "entered_at": "",
        })
    write_csv("order_tests", items)


@app.route("/orders/<order_id>", methods=["GET", "POST"])
def order_detail(order_id):
    order = get_record("orders", order_id)
    if not order:
        flash("Order not found", "error")
        return redirect(url_for("orders_page"))

    if request.method == "POST":
        action = request.form.get("action", "add_tests")
        if action == "add_tests":
            selected = expand_selection(request.form.getlist("profile_ids"), request.form.getlist("test_ids"))
            if selected:
                add_items_to_order(order_id, selected)
                refresh_order_status(order_id)
                flash(f"{len(selected)} test(s) added to {order_id}", "success")
                return redirect(url_for("order_detail", order_id=order_id))
            flash("Select at least one test or profile", "error")

    items = [i for i in read_csv("order_tests") if i["order_id"] == order_id]
    items.sort(key=lambda i: i.get("id", ""))
    t_map = test_map()
    pm = patient_map()
    total = order_total(order_id)
    return render_template(
        "order_detail.html", active="orders",
        order=enrich_order(order), items=items, t_map=t_map,
        patient_name=pm.get(order["patient_id"], order["patient_id"]),
        total=total,
        tests_by_cat=tests_by_category(), profiles=read_csv("profiles"),
        profile_summaries=profile_summary(),
    )


@app.route("/api/order-tests/<item_id>/status", methods=["POST"])
def api_item_status(item_id):
    item_id = safe_id(item_id)
    data = request.get_json(silent=True) or {}
    status = data.get("status", "")
    if status not in LINE_STATUSES:
        return jsonify({"ok": False, "error": "Invalid status"}), 400
    items = read_csv("order_tests")
    for i in items:
        if i["id"] == item_id:
            i["status"] = status
            order_id = i["order_id"]
            write_csv("order_tests", items)
            refresh_order_status(order_id)
            return jsonify({"ok": True, "status": status, "order_status": get_record("orders", order_id)["status"]})
    return jsonify({"ok": False, "error": "Item not found"}), 404


@app.route("/api/order-tests/<item_id>/delete", methods=["POST"])
def api_item_delete(item_id):
    item_id = safe_id(item_id)
    items = read_csv("order_tests")
    order_id = None
    for i in items:
        if i["id"] == item_id:
            order_id = i["order_id"]
            break
    if order_id is None:
        return jsonify({"ok": False, "error": "Item not found"}), 404
    write_csv("order_tests", [i for i in items if i["id"] != item_id])
    refresh_order_status(order_id)
    return jsonify({"ok": True})


@app.route("/api/orders/<order_id>")
def api_order(order_id):
    order = get_record("orders", order_id)
    if not order:
        return jsonify({"ok": False, "error": "Order not found"}), 404
    pm = patient_map()
    t_map = test_map()
    items = []
    for i in read_csv("order_tests"):
        if i["order_id"] != order_id:
            continue
        t = t_map.get(i["test_id"], {})
        items.append({
            "id": i["id"], "test_id": i["test_id"],
            "test_name": t.get("test_name", i["test_id"]),
            "category": t.get("category", ""),
            "status": i["status"], "price": i.get("price", "0"),
            "result_value": i.get("result_value", ""),
            "unit": i.get("unit", "") or t.get("unit", ""),
            "reference_range": i.get("reference_range", "") or t.get("reference_range", ""),
        })
    return jsonify({
        "ok": True,
        "order_id": order_id,
        "patient": pm.get(order["patient_id"], order["patient_id"]),
        "priority": order.get("priority", ""),
        "status": order.get("status", ""),
        "items": items,
    })


# ------------------------- Results -------------------------
@app.route("/results", methods=["GET", "POST"])
def results_page():
    if request.method == "POST":
        order_id = safe_id(request.form.get("order_id", ""))
        item_ids = [safe_id(v) for v in request.form.getlist("item_ids")]
        values = [clean_text(v, 100) for v in request.form.getlist("result_values")]
        units = [clean_text(v, 20) for v in request.form.getlist("units")]
        refs = [clean_text(v, 100) for v in request.form.getlist("reference_ranges")]
        if not order_id or not item_ids or not any(values):
            flash("Select an order and provide a result value", "error")
        else:
            items = read_csv("order_tests")
            saved = 0
            valid_items = {i["id"] for i in items if i["order_id"] == order_id}
            for idx, (iid, val) in enumerate(zip(item_ids, values)):
                val = val.strip()
                if not val or iid not in valid_items:
                    continue
                for i in items:
                    if i["id"] == iid and i["order_id"] == order_id:
                        i["result_value"] = val
                        i["unit"] = units[idx] if idx < len(units) else i["unit"]
                        i["reference_range"] = refs[idx] if idx < len(refs) else i["reference_range"]
                        i["status"] = "Completed"
                        i["entered_at"] = now_ts()
                        saved += 1
                        break
            write_csv("order_tests", items)
            refresh_order_status(order_id)
            if saved:
                flash(f"{saved} result(s) saved for {order_id}", "success")
            else:
                flash("No valid result values were provided", "error")
            return redirect(url_for("results_page"))

    open_orders = [
        enrich_order(o) for o in read_csv("orders")
        if o["status"] in ("Pending", "Collected", "In Progress")
    ]
    open_orders.sort(key=lambda o: o.get("ordered_at", ""), reverse=True)

    t_map = test_map()
    pm = patient_map()
    recent = []
    for i in sorted(read_csv("order_tests"), key=lambda x: x.get("entered_at", ""), reverse=True):
        if i.get("entered_at"):
            o = get_record("orders", i["order_id"])
            t = t_map.get(i["test_id"], {})
            recent.append({
                "id": i["id"], "order_id": i["order_id"],
                "patient": pm.get(o.get("patient_id", ""), "") if o else "",
                "test": t.get("test_name", i["test_id"]),
                "value": i.get("result_value", ""), "unit": i.get("unit", ""),
                "entered_at": i.get("entered_at", ""),
            })
    return render_template(
        "results.html", active="results",
        open_orders=open_orders, recent=recent,
    )


# ------------------------- Reports -------------------------
@app.route("/reports")
def reports_page():
    pm = patient_map()
    t_map = test_map()
    patient_filter = request.args.get("patient", "").strip()
    status_filter = request.args.get("status", "").strip()
    date_filter = request.args.get("date", "").strip()

    rows = []
    for i in read_csv("order_tests"):
        if not i.get("entered_at"):
            continue
        o = get_record("orders", i["order_id"])
        if not o:
            continue
        if patient_filter and o["patient_id"] != patient_filter:
            continue
        if status_filter and i.get("status") != status_filter:
            continue
        if date_filter and date_filter not in i.get("entered_at", ""):
            continue
        t = t_map.get(i["test_id"], {})
        rows.append({
            "item": i,
            "order_id": i["order_id"],
            "patient": pm.get(o["patient_id"], o["patient_id"]),
            "test": t.get("test_name", i["test_id"]),
            "category": t.get("category", ""),
            "ordered_at": o.get("ordered_at", ""),
        })

    revenue = sum(float(r["item"].get("price", 0) or 0) for r in rows if r["item"].get("status") == "Completed")
    return render_template(
        "reports.html", active="reports", rows=rows,
        patients=read_csv("patients"), revenue=revenue,
    )


# ------------------------- Delete API -------------------------
@app.route("/api/delete/<name>/<record_id>", methods=["POST"])
def api_delete(name, record_id):
    if name not in CSV_FILES:
        return jsonify({"ok": False, "error": "Invalid table"}), 400
    record_id = safe_id(record_id)
    rows = read_csv(name)
    new_rows = [r for r in rows if r.get("id") != record_id]
    if len(new_rows) == len(rows):
        return jsonify({"ok": False, "error": "Record not found"}), 404
    write_csv(name, new_rows)
    return jsonify({"ok": True})


# ------------------------- startup seed -------------------------
ensure_data_files()

with app.app_context():
    if not read_csv("users"):
        write_csv("users", [{
            "id": "USR0001", "username": "admin",
            "full_name": "System Administrator", "role": "admin",
            "password_hash": generate_password_hash("admin123"),
            "must_change": "1", "created_at": now_ts(),
        }])

    if not read_csv("tests"):
        write_csv("tests", [
            # Hematology
            {"id": "TST0001", "test_name": "Complete Blood Count (CBC)", "category": "Hematology", "price": "450", "turnaround_hours": "6", "reference_range": "See report", "unit": ""},
            {"id": "TST0002", "test_name": "Hemoglobin (Hb)", "category": "Hematology", "price": "120", "turnaround_hours": "4", "reference_range": "12-16 g/dL", "unit": "g/dL"},
            {"id": "TST0003", "test_name": "ESR", "category": "Hematology", "price": "150", "turnaround_hours": "6", "reference_range": "0-20 mm/hr", "unit": "mm/hr"},
            {"id": "TST0004", "test_name": "Blood Grouping & Rh", "category": "Hematology", "price": "180", "turnaround_hours": "4", "reference_range": "NA", "unit": ""},
            {"id": "TST0005", "test_name": "PT / INR", "category": "Hematology", "price": "320", "turnaround_hours": "8", "reference_range": "INR 0.8-1.2", "unit": "INR"},
            # Biochemistry
            {"id": "TST0006", "test_name": "Blood Glucose (Fasting)", "category": "Biochemistry", "price": "180", "turnaround_hours": "4", "reference_range": "70-100 mg/dL", "unit": "mg/dL"},
            {"id": "TST0007", "test_name": "Blood Glucose (Post Prandial)", "category": "Biochemistry", "price": "180", "turnaround_hours": "4", "reference_range": "70-140 mg/dL", "unit": "mg/dL"},
            {"id": "TST0008", "test_name": "HbA1c", "category": "Biochemistry", "price": "450", "turnaround_hours": "12", "reference_range": "< 5.7 %", "unit": "%"},
            {"id": "TST0009", "test_name": "Lipid Profile", "category": "Biochemistry", "price": "600", "turnaround_hours": "8", "reference_range": "See report", "unit": "mg/dL"},
            {"id": "TST0010", "test_name": "Liver Function Test (LFT)", "category": "Biochemistry", "price": "550", "turnaround_hours": "8", "reference_range": "See report", "unit": ""},
            {"id": "TST0011", "test_name": "Renal Function Test (RFT)", "category": "Biochemistry", "price": "500", "turnaround_hours": "8", "reference_range": "See report", "unit": ""},
            {"id": "TST0012", "test_name": "Serum Electrolytes", "category": "Biochemistry", "price": "420", "turnaround_hours": "8", "reference_range": "Na 135-145, K 3.5-5.1", "unit": "mmol/L"},
            {"id": "TST0013", "test_name": "Uric Acid", "category": "Biochemistry", "price": "280", "turnaround_hours": "6", "reference_range": "3.4-7.0 mg/dL", "unit": "mg/dL"},
            {"id": "TST0014", "test_name": "Calcium", "category": "Biochemistry", "price": "250", "turnaround_hours": "6", "reference_range": "8.5-10.5 mg/dL", "unit": "mg/dL"},
            # Endocrinology
            {"id": "TST0015", "test_name": "Thyroid Profile (T3, T4, TSH)", "category": "Endocrinology", "price": "750", "turnaround_hours": "12", "reference_range": "TSH 0.4-4.0 uIU/mL", "unit": "uIU/mL"},
            {"id": "TST0016", "test_name": "Vitamin D (25-OH)", "category": "Endocrinology", "price": "900", "turnaround_hours": "24", "reference_range": "30-100 ng/mL", "unit": "ng/mL"},
            {"id": "TST0017", "test_name": "Vitamin B12", "category": "Endocrinology", "price": "850", "turnaround_hours": "24", "reference_range": "200-900 pg/mL", "unit": "pg/mL"},
            # Serology
            {"id": "TST0018", "test_name": "Dengue NS1 Antigen", "category": "Serology", "price": "700", "turnaround_hours": "8", "reference_range": "Negative", "unit": ""},
            {"id": "TST0019", "test_name": "Widal Test", "category": "Serology", "price": "300", "turnaround_hours": "8", "reference_range": "< 1:80", "unit": ""},
            {"id": "TST0020", "test_name": "HBsAg (Hepatitis B)", "category": "Serology", "price": "400", "turnaround_hours": "8", "reference_range": "Non-reactive", "unit": ""},
            {"id": "TST0021", "test_name": "HIV 1 & 2 Antibody", "category": "Serology", "price": "500", "turnaround_hours": "8", "reference_range": "Non-reactive", "unit": ""},
            # Microbiology / Urine
            {"id": "TST0022", "test_name": "Urine Routine & Microscopy", "category": "Microbiology", "price": "200", "turnaround_hours": "6", "reference_range": "See report", "unit": ""},
            {"id": "TST0023", "test_name": "Urine Culture & Sensitivity", "category": "Microbiology", "price": "450", "turnaround_hours": "48", "reference_range": "No growth", "unit": ""},
            {"id": "TST0024", "test_name": "Stool Routine & Occult Blood", "category": "Microbiology", "price": "220", "turnaround_hours": "8", "reference_range": "Negative", "unit": ""},
            # Cardiology
            {"id": "TST0025", "test_name": "ECG (12 Lead)", "category": "Cardiology", "price": "350", "turnaround_hours": "24", "reference_range": "Normal", "unit": ""},
            {"id": "TST0026", "test_name": "2D Echocardiography", "category": "Cardiology", "price": "1800", "turnaround_hours": "24", "reference_range": "See report", "unit": ""},
            {"id": "TST0027", "test_name": "Troponin I", "category": "Cardiology", "price": "950", "turnaround_hours": "12", "reference_range": "< 0.04 ng/mL", "unit": "ng/mL"},
            # Radiology
            {"id": "TST0028", "test_name": "X-Ray Chest (PA View)", "category": "Radiology", "price": "500", "turnaround_hours": "24", "reference_range": "NA", "unit": ""},
            {"id": "TST0029", "test_name": "USG Abdomen & Pelvis", "category": "Radiology", "price": "1500", "turnaround_hours": "24", "reference_range": "See report", "unit": ""},
            {"id": "TST0030", "test_name": "CT Scan Brain (Plain)", "category": "Radiology", "price": "3200", "turnaround_hours": "24", "reference_range": "See report", "unit": ""},
        ])

    if not read_csv("profiles"):
        def _link(pid, *tests):
            return [{"profile_id": pid, "test_id": t} for t in tests]

        write_csv("profiles", [
            {"id": "PRF0001", "profile_name": "Basic Health Package", "description": "Core screening panel", "created_at": now_ts()},
            {"id": "PRF0002", "profile_name": "Full Body Checkup", "description": "Comprehensive annual checkup", "created_at": now_ts()},
            {"id": "PRF0003", "profile_name": "Diabetes Care Panel", "description": "Monitoring for diabetic patients", "created_at": now_ts()},
            {"id": "PRF0004", "profile_name": "Cardiac Risk Panel", "description": "Heart health screening", "created_at": now_ts()},
            {"id": "PRF0005", "profile_name": "Kidney Function Panel", "description": "Renal health screening", "created_at": now_ts()},
        ])
        write_csv("profile_tests",
            _link("PRF0001", "TST0001", "TST0006", "TST0022", "TST0010") +
            _link("PRF0002", "TST0001", "TST0006", "TST0009", "TST0010", "TST0011", "TST0015", "TST0022", "TST0008") +
            _link("PRF0003", "TST0006", "TST0007", "TST0008", "TST0011", "TST0022", "TST0009") +
            _link("PRF0004", "TST0009", "TST0025", "TST0027", "TST0012") +
            _link("PRF0005", "TST0011", "TST0012", "TST0013", "TST0014", "TST0022")
        )

    if not read_csv("patients"):
        write_csv("patients", [
            {"id": "PAT0001", "name": "Ramesh Kumar", "age": "45", "gender": "Male", "phone": "9840012345", "email": "ramesh.k@gmail.com", "doctor": "Dr. Meena", "created_at": now_ts()},
            {"id": "PAT0002", "name": "Priya Sharma", "age": "32", "gender": "Female", "phone": "9950022334", "email": "priya.s@yahoo.com", "doctor": "Dr. Arjun", "created_at": now_ts()},
            {"id": "PAT0003", "name": "Suresh Babu", "age": "58", "gender": "Male", "phone": "9776655443", "email": "suresh.b@gmail.com", "doctor": "Dr. Meena", "created_at": now_ts()},
            {"id": "PAT0004", "name": "Anitha Devi", "age": "28", "gender": "Female", "phone": "9445678123", "email": "anitha.d@gmail.com", "doctor": "Dr. Karthik", "created_at": now_ts()},
            {"id": "PAT0005", "name": "Mohan Raj", "age": "63", "gender": "Male", "phone": "9886543210", "email": "mohan.r@gmail.com", "doctor": "Dr. Meena", "created_at": now_ts()},
        ])


if __name__ == "__main__":
    debug = os.environ.get("LAB_DEBUG", "").strip() == "1"
    app.run(debug=debug, host="0.0.0.0", port=5001)
