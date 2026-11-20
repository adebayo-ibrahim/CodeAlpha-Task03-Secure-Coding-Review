"""
Runs the same attacks against vulnerable_app.py and secure_app.py and shows which ones work.

    pip install flask
    python test_security.py

Nothing is sent over the network: the attacks go straight into the two Flask apps inside this program.
"""

import ast
import base64
import hashlib
import importlib
import os
import pickle
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path

from flask import Flask
from flask.sessions import SecureCookieSessionInterface

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
WORK = Path(tempfile.mkdtemp(prefix="notevault_test_"))
FILES_EXISTED = (HERE / "files").exists()
LEAKED_KEY = None   # filled in by run(): the secret key anyone can read in vulnerable_app.py

# The secure app takes its admin password from the environment, so the test sets a known one.
os.environ["NOTEVAULT_ADMIN_PASSWORD"] = "test-only-admin-password"


def load(name):
    os.environ["NOTEVAULT_DB"] = str(WORK / f"{name}.db")
    module = importlib.import_module(name)
    module.app.logger.disabled = True      # keep the output clean when an attack crashes the app
    module.init_files()
    module.init_db()
    return module


def ensure_ping():
    """On a computer without ping (some containers) put a stand-in on the PATH, so the ping checks still mean something."""
    if shutil.which("ping") or os.name == "nt":
        return
    folder = WORK / "bin"
    folder.mkdir()
    program = folder / "ping"
    program.write_text("#!/bin/sh\necho stand-in ping $@\n")
    program.chmod(0o755)
    os.environ["PATH"] = str(folder) + os.pathsep + os.environ["PATH"]
    print("Note: ping is not installed on this computer, so a stand-in ping is used for the ping checks.\n")


def logged_in(m, username, password):
    client = m.app.test_client()
    client.post("/login", data={"username": username, "password": password})
    return client


def text_of(response):
    return response.get_data(as_text=True)


def stored_hashes(m):
    with closing(sqlite3.connect(m.DB_FILE)) as db:
        return [row[0] for row in db.execute("SELECT password FROM users")]


class Evil:
    """A pickle that runs code (it creates an empty file) as soon as it is loaded."""

    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (exec, (f"open({self.marker!r}, 'w').close()",))


# Each attack returns True when it WORKS (the app is vulnerable) and False when the app stops it.

def f1_login_bypass(m):
    response = m.app.test_client().post("/login", data={"username": "admin' --", "password": "wrong"})
    return response.status_code == 200 and "Welcome, admin" in text_of(response)


def f2_union_sqli(m):
    client = logged_in(m, "alice", "alice-pass-1")
    response = client.get("/search", query_string={"q": "zzz' UNION SELECT username, password FROM users --"})
    return any(h in text_of(response) for h in stored_hashes(m))


def f3_command_injection(m):
    if os.name == "nt":
        payload = "127.0.0.1 & set /a 424242+1"
    else:
        payload = "127.0.0.1 ; echo $((424242+1))"
    outsider = m.app.test_client()
    if "424243" in text_of(outsider.get("/ping", query_string={"host": payload})):
        return True
    admin = logged_in(m, "admin", m.ADMIN_PASSWORD)          # even a real admin must not be able to inject
    return "424243" in text_of(admin.get("/ping", query_string={"host": payload}))


def f4_pickle_cookie(m):
    marker = WORK / f"pickle_marker_{m.__name__}.txt"
    cookie = base64.b64encode(pickle.dumps(Evil(str(marker)))).decode()
    client = m.app.test_client()
    client.set_cookie("remember", cookie)
    client.get("/whoami")
    return marker.exists()


def f5_forged_session(m):
    attacker_app = Flask("attacker")
    attacker_app.secret_key = LEAKED_KEY
    forged = SecureCookieSessionInterface().get_signing_serializer(attacker_app).dumps(
        {"user_id": 1, "username": "admin", "role": "admin"})
    client = m.app.test_client()
    client.set_cookie("session", forged)
    response = client.get("/admin")
    return response.status_code == 200 and "All users" in text_of(response)


def f5_default_password(m):
    response = m.app.test_client().post("/login", data={"username": "admin", "password": "admin123"})
    return response.status_code == 200


def f6_weak_hash(m):
    with closing(sqlite3.connect(m.DB_FILE)) as db:
        stored = db.execute("SELECT password FROM users WHERE username = 'alice'").fetchone()[0]
    return stored == hashlib.md5(b"alice-pass-1").hexdigest()


def f7_path_traversal(m):
    client = logged_in(m, "alice", "alice-pass-1")
    response = client.get("/download", query_string={"file": f"../{m.__name__}.py"})
    return response.status_code == 200 and "def init_db" in text_of(response)


def f8_xss(m):
    client = logged_in(m, "alice", "alice-pass-1")
    payload = "<script>alert(1)</script>"
    return payload in text_of(client.get("/search", query_string={"q": payload}))


def f9_idor(m):
    client = logged_in(m, "alice", "alice-pass-1")
    response = client.get("/profile/1")                       # user 1 is the admin
    return response.status_code == 200 and "admin@notevault.local" in text_of(response)


def f9_no_login(m):
    client = m.app.test_client()
    download = client.get("/download", query_string={"file": "welcome.txt"})
    ping = client.get("/ping", query_string={"host": "127.0.0.1"})
    return download.status_code not in (401, 403) or ping.status_code not in (401, 403)


def f10_debug_bind_all(m):
    tree = ast.parse(Path(m.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        is_app_run = (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                      and node.func.attr == "run" and getattr(node.func.value, "id", "") == "app")
        if is_app_run:
            options = {k.arg: getattr(k.value, "value", None) for k in node.keywords}
            return options.get("debug") is True or options.get("host") == "0.0.0.0"
    return False


def f11_no_lockout(m):
    for _ in range(8):
        m.app.test_client().post("/login", data={"username": "bob", "password": "wrong-guess"})
    response = m.app.test_client().post("/login", data={"username": "bob", "password": "bob-pass-2"})
    return response.status_code == 200                        # still accepted after 8 wrong guesses


def f12_headers(m):
    client = m.app.test_client()
    home = client.get("/")
    login = client.post("/login", data={"username": "alice", "password": "alice-pass-1"})
    cookies = " ".join(login.headers.getlist("Set-Cookie"))
    missing_headers = "Content-Security-Policy" not in home.headers or "X-Content-Type-Options" not in home.headers
    return missing_headers or "SameSite" not in cookies


# Normal use must keep working in both versions. Without these checks a broken app would also "block" every attack.
# Each check returns True (works), False (broken) or None (cannot be checked on this computer).

def c_login(m):
    response = m.app.test_client().post("/login", data={"username": "alice", "password": "alice-pass-1"})
    return response.status_code == 200 and "Welcome, alice" in text_of(response)


def c_search(m):
    client = logged_in(m, "alice", "alice-pass-1")
    return "milk, eggs, bread" in text_of(client.get("/search", query_string={"q": "Shopping"}))


def c_own_profile(m):
    response = logged_in(m, "alice", "alice-pass-1").get("/profile/2")
    return response.status_code == 200 and "alice@example.com" in text_of(response)


def c_admin_page(m):
    response = logged_in(m, "admin", m.ADMIN_PASSWORD).get("/admin")
    return response.status_code == 200 and "alice@example.com" in text_of(response)


def c_download(m):
    response = logged_in(m, "alice", "alice-pass-1").get("/download", query_string={"file": "welcome.txt"})
    return response.status_code == 200 and "Welcome to NoteVault" in text_of(response)


def c_ping(m):
    if shutil.which("ping") is None:
        return None
    response = logged_in(m, "admin", m.ADMIN_PASSWORD).get("/ping", query_string={"host": "127.0.0.1"})
    return response.status_code == 200


CONTROLS = [
    ("Log in with the right password", c_login),
    ("Search your own notes", c_search),
    ("Open your own profile", c_own_profile),
    ("Admin opens the user list", c_admin_page),
    ("Download the welcome file", c_download),
    ("Admin pings 127.0.0.1", c_ping),
]

TESTS = [
    ("F1", "SQL injection: log in as admin without the password", f1_login_bypass),
    ("F2", "SQL injection: read all password hashes via the search box", f2_union_sqli),
    ("F3", "Command injection through the ping tool", f3_command_injection),
    ("F4", "Code execution through the pickled 'remember' cookie", f4_pickle_cookie),
    ("F5", "Forged admin session using the key found in the source code", f5_forged_session),
    ("F5", "Admin login with the password found in the source code", f5_default_password),
    ("F6", "Passwords stored as unsalted MD5", f6_weak_hash),
    ("F7", "Path traversal: download the app's own source code", f7_path_traversal),
    ("F8", "Cross-site scripting through the search box", f8_xss),
    ("F9", "Read another user's profile (IDOR)", f9_idor),
    ("F9", "Use /ping and /download without logging in", f9_no_login),
    ("F10", "Debug mode on and listening on all network interfaces", f10_debug_bind_all),
    ("F11", "Unlimited password guesses (no lockout)", f11_no_lockout),
    ("F12", "Missing security headers and cookie SameSite flag", f12_headers),
]


def run():
    global LEAKED_KEY
    ensure_ping()
    vulnerable = load("vulnerable_app")
    secure = load("secure_app")
    LEAKED_KEY = vulnerable.SECRET_KEY

    print(f"{'ID':<5}{'Attack':<62}{'vulnerable_app':<16}secure_app")
    print("-" * 95)
    all_good = True
    for finding, title, attack in TESTS:
        works_on_vulnerable = attack(vulnerable)
        works_on_secure = attack(secure)
        print(f"{finding:<5}{title:<62}{'VULNERABLE' if works_on_vulnerable else 'safe':<16}"
              f"{'VULNERABLE' if works_on_secure else 'safe'}")
        all_good = all_good and works_on_vulnerable and not works_on_secure
    print("-" * 95)
    print("Normal use must still work (a fix that breaks the app is not a fix):")
    for title, check in CONTROLS:
        outcomes = []
        for module in (vulnerable, secure):
            result = check(module)
            outcomes.append("skipped" if result is None else ("ok" if result else "BROKEN"))
            all_good = all_good and result is not False
        print(f"{'':<5}{title:<62}{outcomes[0]:<16}{outcomes[1]}")
    print("-" * 95)
    if all_good:
        print("Result: every attack works on vulnerable_app.py, none works on secure_app.py, normal use still works.")
    else:
        print("Result: unexpected outcome, check the rows above.")
    return 0 if all_good else 1


if __name__ == "__main__":
    try:
        code = run()
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
        if not FILES_EXISTED:
            shutil.rmtree(HERE / "files", ignore_errors=True)
    sys.exit(code)
