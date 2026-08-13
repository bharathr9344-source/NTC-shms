# Secure Hospital Laboratory Management System

A secure, CSV-backed web application for managing a hospital diagnostic laboratory. Built with **Flask** (Python), **HTML**, **CSS** and **JavaScript**, featuring a professional white and blue interface.

The system covers the full lab workflow: patient registration, a rich test catalog, reusable test profiles/packages, multi-test orders, per-test results entry, reporting and revenue tracking — all protected by enterprise-grade security controls.

---

## Features

- **Dashboard** — live overview: patients, tests, profiles, open/completed orders, revenue and tests-by-category breakdown.
- **Patient Management** — register, list, search and delete patients.
- **Test Catalog** — add/remove any diagnostic test (name, category, price, turnaround, reference range, unit). Seeded with 30 tests across 9 categories.
- **Profiles & Packages** — bundle multiple tests into reusable health packages (e.g. "Full Body Checkup"); auto-expand into individual line items when ordered; duplicate tests are merged automatically.
- **Test Orders** — create one order containing any mix of profiles and individual tests via a searchable multi-select picker; add more tests to an order at any time; per-line-item status tracking (Pending / Collected / In Progress / Completed / Cancelled) with automatic order-level status.
- **Results Entry** — pick an open order, all pending tests load with pre-filled units and reference ranges, save results for all tests at once.
- **Reports** — filter records by patient/status/date, revenue totals, print-friendly output.
- **User Management** (admin) — create users, reset passwords, delete accounts; role-based access (admin / staff).

---

## Security

The application was built with security as a first-class requirement:

| Control | Implementation |
| --- | --- |
| Authentication | Session-based login; passwords hashed with `werkzeug` scrypt/pbkdf2 (salted, never plain text). |
| Brute-force protection | 5 failed attempts locks an account (per username + IP) for 15 minutes. |
| Forced password change | Default/reset credentials must be changed on first sign-in. |
| CSRF protection | Per-session token validated on every state-changing request (forms and JSON APIs). |
| Session cookies | `HttpOnly`, `SameSite=Lax`, 8-hour lifetime, optional `Secure` flag. |
| Secret key | Random 256-bit key persisted to `data/.secret_key` (mode 600); overridable via environment variable. |
| Security headers | Content-Security-Policy, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`. |
| CSV injection | Formula cells (`=`, `+`, `@`, `-`) neutralised on write and cleaned on read. |
| Input validation | Whitelists for statuses, priorities, roles, IDs; length caps; numeric checks; safe redirect handling. |
| XSS protection | Jinja auto-escaping plus explicit HTML escaping in dynamic JavaScript-rendered content. |
| Error handling | Custom 403/404/413/500 pages that never leak stack traces. |
| File permissions | `data/` directory `700`, `data/users.csv` and `data/.secret_key` `600`. |
| Debug mode | Disabled by default; enable only via `LAB_DEBUG=1`. |

---

## Technology Stack

- **Backend:** Python 3.10+, Flask 3.x
- **Storage:** CSV files (`data/`) — no database server required
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (no external CDN dependencies)
- **Password hashing:** `werkzeug.security`

---

## Requirements

- Python 3.10 or newer
- A virtual environment (recommended)
- Dependencies listed in `requirements.txt`:
  - Flask
  - python-dotenv
  - Werkzeug
  - blinker

---

## Installation & Setup

```bash
# 1. Clone or navigate into the project
cd leboratory

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Configure environment variables
export LAB_SSL=1                  # Enable Secure session cookies (HTTPS)
export LAB_DEBUG=1                # Enable Flask debug mode (development only)
export LAB_SECRET_KEY="..."       # Override the auto-generated secret key

# 5. Run the application
python app.py
```

Open your browser at **http://127.0.0.1:5001**

---

## Default Credentials

On first run the system creates an administrator account:

| Username | Password | Role |
| --- | --- | --- |
| `admin` | `admin123` | admin |

**Security note:** the default password is forced to change on the first sign-in. After changing it, use the **Users & Access** page (admin) to create accounts for staff.

---

## Configuration (Environment Variables)

| Variable | Default | Description |
| --- | --- | --- |
| `LAB_SECRET_KEY` | auto-generated | Overrides the session signing key. |
| `LAB_DEBUG` | `0` (off) | Set to `1` for development debug mode. |
| `LAB_SSL` | `0` (off) | Set to `1` to send session cookies only over HTTPS. |

---

## Data Storage (CSV Layout)

All data lives in the `data/` directory and is created automatically on startup. Sample data is seeded on first run.

| File | Purpose | Key columns |
| --- | --- | --- |
| `users.csv` | User accounts | id, username, full_name, role, password_hash, must_change |
| `patients.csv` | Registered patients | id, name, age, gender, phone, email, doctor |
| `tests.csv` | Test catalog | id, test_name, category, price, turnaround_hours, reference_range, unit |
| `profiles.csv` | Test bundles/packages | id, profile_name, description |
| `profile_tests.csv` | Profile <-> test mapping | profile_id, test_id |
| `orders.csv` | Order headers | id, patient_id, priority, status, requested_by, ordered_at |
| `order_tests.csv` | Order line items | id, order_id, test_id, price, status, result_value, unit, reference_range, entered_at |

> Back up the `data/` directory to preserve all records. Restoring a backup is a simple file copy.

---

## Project Structure

```
leboratory/
├── app.py                  # Flask backend, CSV data layer, routes, security
├── requirements.txt        # Python dependencies
├── data/                   # CSV data files (auto-created)
│   ├── users.csv
│   ├── patients.csv
│   ├── tests.csv
│   ├── profiles.csv
│   ├── profile_tests.csv
│   ├── orders.csv
│   └── order_tests.csv
├── static/
│   ├── css/
│   │   └── style.css       # White & blue professional theme, responsive, print styles
│   └── js/
│       └── main.js         # Modals, toasts, search, picker, CSRF/escaping helpers
└── templates/
    ├── base.html           # Layout: sidebar, topbar, user menu, flash messages
    ├── login.html          # Standalone secure login page
    ├── change_password.html
    ├── users.html          # Admin user management
    ├── dashboard.html
    ├── patients.html
    ├── tests.html
    ├── profiles.html
    ├── orders.html         # Order list + multi-select picker modal
    ├── order_detail.html   # Per-line-item status, add/remove tests
    ├── results.html        # Per-test result entry
    ├── reports.html
    ├── error.html          # 403 / 404 / 413 / 500 pages
    └── _picker.html        # Reusable searchable test/profile picker macro
```

---

## Usage Workflow

1. **Sign in** with your username and password (change the default password when prompted).
2. **Register patients** under *Patients*.
3. **Build the catalog** under *Test Catalog* / *Profiles & Packages*.
4. **Create a test order** under *Test Orders* — select a patient, then tick any combination of tests and profiles.
5. **Track the order** — update each test's status (Collected, In Progress, etc.) from the order detail page.
6. **Enter results** under *Results* — pick the open order, fill in values, save.
7. **Review reports** under *Reports* — filter and print.

---

## REST/JSON APIs

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/orders/<order_id>` | GET | Order details with line items (used by results page). |
| `/api/order-tests/<item_id>/status` | POST | Update a line item's status. |
| `/api/order-tests/<item_id>/delete` | POST | Remove a test from an order. |
| `/api/delete/<table>/<record_id>` | POST | Delete a record from a table. |
| `/api/dashboard` | GET | Dashboard status counts. |

All POST endpoints require the session CSRF token (sent as the `X-CSRF-Token` header for JSON calls).

---

## Development Notes

- **Adding a new test:** open *Test Catalog* -> *Add Test* (no code changes required).
- **Adding a new profile/package:** open *Profiles & Packages* -> tick the tests to bundle.
- **Debugging locally:** run with `LAB_DEBUG=1 python app.py`. Never enable debug mode in production.
- **Deployment:** for production, run behind a WSGI server (e.g. gunicorn) and a reverse proxy (nginx) with HTTPS, and set `LAB_SSL=1`.

---

## License

This project is for educational and internal hospital use.
