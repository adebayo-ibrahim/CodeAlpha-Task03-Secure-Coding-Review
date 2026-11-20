"""
NoteVault, the FIXED version of vulnerable_app.py (CodeAlpha, Task 3).
Every change is explained in REVIEW_REPORT.md.

Run:  pip install flask   then   python secure_app.py   then open http://127.0.0.1:5000

Settings are read from environment variables, never from the source code:
  NOTEVAULT_SECRET_KEY      signs the session cookie (a random key is made for each run if it is not set)
  NOTEVAULT_ADMIN_PASSWORD  password of the admin account (a random one is made and printed if it is not set)
  NOTEVAULT_HTTPS=1         set it when the app is served over HTTPS, so the session cookie is marked Secure
Demo accounts: alice (password alice-pass-1) and bob (password bob-pass-2). They exist for this exercise only.
"""

import functools
import ipaddress
import os
import secrets
import shutil
import sqlite3
# subprocess is used without a shell and only with a validated IP address (see ping()).
import subprocess  # nosec B404
import time
from contextlib import closing
from datetime import timedelta

from flask import Flask, abort, g, render_template_string, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

ADMIN_PASSWORD_FROM_ENV = os.environ.get("NOTEVAULT_ADMIN_PASSWORD")
SECRET_KEY = os.environ.get("NOTEVAULT_SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = ADMIN_PASSWORD_FROM_ENV or secrets.token_urlsafe(12)
DB_FILE = os.environ.get("NOTEVAULT_DB", "notevault.db")
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
MAX_FAILED_LOGINS = 5     # wrong passwords allowed ...
LOCKOUT_SECONDS = 300     # ... within this many seconds

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NOTEVAULT_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)
failed_logins = {}   # "ip:username" -> [number of failures, time of the first one]

PAGE = """
<h1>NoteVault</h1>
<form method="post" action="/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Log in</button>
</form>
<form action="/search"><input name="q" placeholder="search my notes"><button>Search</button></form>
<form action="/ping"><input name="host" placeholder="IP address to ping"><button>Ping</button></form>
<p><a href="/download?file=welcome.txt">Welcome file</a> |
   <a href="/profile/2">My profile</a> | <a href="/whoami">Who am I?</a> | <a href="/admin">Admin</a></p>
"""

# Templates escape every {{ value }} automatically, so user input can never become HTML.
RESULTS_TEMPLATE = """
<h2>Results for: {{ q }}</h2>
{% for row in rows %}<h3>{{ row['title'] }}</h3><p>{{ row['body'] }}</p>{% endfor %}
"""
USERS_TEMPLATE = """
<h2>All users</h2>
{% for u in users %}{{ u['username'] }} - {{ u['email'] }} - {{ u['role'] }}<br>{% endfor %}
"""


def query(sql, params=()):
    """Run one SQL statement. Values always travel in `params`, never inside `sql`."""
    with closing(sqlite3.connect(DB_FILE)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(sql, params).fetchall()
        db.commit()
        return rows


def init_db():
    with closing(sqlite3.connect(DB_FILE)) as db:
        db.executescript("""
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS notes;
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, role TEXT);
            CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);
        """)
        users = [
            ("admin", ADMIN_PASSWORD, "admin@notevault.local", "admin"),
            ("alice", "alice-pass-1", "alice@example.com", "user"),   # demo accounts for this exercise only
            ("bob", "bob-pass-2", "bob@example.com", "user"),
        ]
        for username, password, email, role in users:
            db.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                       (username, generate_password_hash(password), email, role))
        db.executemany("INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)", [
            ("admin", "Quarterly report", "numbers are due on Friday"),
            ("alice", "Shopping list", "milk, eggs, bread"),
            ("alice", "Project ideas", "write a network scanner"),
            ("bob", "Diary", "met Alice at the library"),
        ])
        db.commit()


def init_files():
    os.makedirs(FILES_DIR, exist_ok=True)
    welcome = os.path.join(FILES_DIR, "welcome.txt")
    if not os.path.exists(welcome):
        with open(welcome, "w") as file:
            file.write("Welcome to NoteVault!\n")


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def current_user():
    """The logged-in user, read from the database on every request (the session only holds the id)."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    rows = query("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    return rows[0] if rows else None


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        g.user = current_user()
        if g.user is None:
            return "Please log in first", 401
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return login_required(wrapper)


def is_locked(key):
    entry = failed_logins.get(key)
    if entry is None:
        return False
    if time.time() - entry[1] > LOCKOUT_SECONDS:
        del failed_logins[key]
        return False
    return entry[0] >= MAX_FAILED_LOGINS


def record_failure(key):
    entry = failed_logins.get(key)
    if entry is None or time.time() - entry[1] > LOCKOUT_SECONDS:
        failed_logins[key] = [1, time.time()]
    else:
        entry[0] += 1


@app.route("/")
def index():
    return PAGE


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    key = f"{request.remote_addr}:{username.lower()}"
    if is_locked(key):
        return "Too many failed attempts. Try again in a few minutes.", 429
    rows = query("SELECT id, username, password FROM users WHERE username = ?", (username,))
    if not rows or not check_password_hash(rows[0]["password"], password):
        record_failure(key)
        return "Invalid username or password", 401
    failed_logins.pop(key, None)
    session.clear()
    session["user_id"] = rows[0]["id"]
    session.permanent = True
    return render_template_string("Welcome, {{ name }}", name=rows[0]["username"])


@app.route("/whoami")
@login_required
def whoami():
    return render_template_string("Logged in as {{ name }}", name=g.user["username"])


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    rows = query("SELECT title, body FROM notes WHERE owner = ? AND title LIKE ?", (g.user["username"], f"%{q}%"))
    return render_template_string(RESULTS_TEMPLATE, q=q, rows=rows)


@app.route("/ping")
@admin_required
def ping():
    try:
        address = str(ipaddress.ip_address(request.args.get("host", "127.0.0.1")))
    except ValueError:
        return "Please enter a valid IP address.", 400
    ping_program = shutil.which("ping")
    if ping_program is None:
        return "ping is not available on this computer.", 500
    count_flag = "-n" if os.name == "nt" else "-c"
    command = [ping_program, count_flag, "1", address]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)  # nosec B603
    except subprocess.TimeoutExpired:
        return "The ping timed out.", 504
    return render_template_string("<pre>{{ output }}</pre>", output=result.stdout + result.stderr)


@app.route("/download")
@login_required
def download():
    name = request.args.get("file", "welcome.txt")
    return send_from_directory(FILES_DIR, name, as_attachment=True)


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    if user_id != g.user["id"] and g.user["role"] != "admin":
        abort(403)
    rows = query("SELECT username, email, role FROM users WHERE id = ?", (user_id,))
    if not rows:
        abort(404)
    return render_template_string("{{ u['username'] }} ({{ u['role'] }}) - {{ u['email'] }}", u=rows[0])


@app.route("/admin")
@admin_required
def admin():
    return render_template_string(USERS_TEMPLATE, users=query("SELECT username, email, role FROM users"))


if __name__ == "__main__":
    init_files()
    init_db()
    if not ADMIN_PASSWORD_FROM_ENV:
        print(f"Admin password for this run: {ADMIN_PASSWORD}")
    app.run(host="127.0.0.1", port=5000, debug=False)
