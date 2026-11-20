"""
NoteVault: a small notes web app that was written to be reviewed (CodeAlpha, Task 3).

WARNING: this app is INTENTIONALLY INSECURE.
Run it only on your own computer and never put it on a network or on the internet.
The findings are in REVIEW_REPORT.md and the fixed version is secure_app.py.

Run:  pip install flask   then   python vulnerable_app.py   then open http://127.0.0.1:5000
Demo accounts: admin, alice (password alice-pass-1), bob (password bob-pass-2)
"""

import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, make_response, request, send_file, session

SECRET_KEY = "notevault-secret-2024"
ADMIN_PASSWORD = "admin123"
DB_FILE = os.environ.get("NOTEVAULT_DB", "notevault.db")
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")

app = Flask(__name__)
app.secret_key = SECRET_KEY

PAGE = """
<h1>NoteVault</h1>
<form method="post" action="/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Log in</button>
</form>
<form action="/search"><input name="q" placeholder="search my notes"><button>Search</button></form>
<form action="/ping"><input name="host" placeholder="host to ping"><button>Ping</button></form>
<p><a href="/download?file=welcome.txt">Welcome file</a> |
   <a href="/profile/2">My profile</a> | <a href="/whoami">Who am I?</a> | <a href="/admin">Admin</a></p>
"""


def get_db():
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    return db


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    db = get_db()
    db.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, role TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);
    """)
    users = [
        ("admin", ADMIN_PASSWORD, "admin@notevault.local", "admin"),
        ("alice", "alice-pass-1", "alice@example.com", "user"),
        ("bob", "bob-pass-2", "bob@example.com", "user"),
    ]
    for username, password, email, role in users:
        db.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                   (username, hash_password(password), email, role))
    db.executemany("INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)", [
        ("admin", "Quarterly report", "numbers are due on Friday"),
        ("alice", "Shopping list", "milk, eggs, bread"),
        ("alice", "Project ideas", "write a network scanner"),
        ("bob", "Diary", "met Alice at the library"),
    ])
    db.commit()
    db.close()


def init_files():
    os.makedirs(FILES_DIR, exist_ok=True)
    welcome = os.path.join(FILES_DIR, "welcome.txt")
    if not os.path.exists(welcome):
        with open(welcome, "w") as file:
            file.write("Welcome to NoteVault!\n")


@app.route("/")
def index():
    return PAGE


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, hash_password(password))
    user = get_db().execute(query).fetchone()
    if user is None:
        return "Invalid username or password", 401
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    response = make_response("Welcome, " + user["username"])
    remember = base64.b64encode(pickle.dumps({"username": user["username"]}))
    response.set_cookie("remember", remember.decode())
    return response


@app.route("/whoami")
def whoami():
    if "username" in session:
        return "Logged in as " + session["username"]
    remember = request.cookies.get("remember")
    if remember:
        data = pickle.loads(base64.b64decode(remember))
        return "Welcome back, " + data["username"]
    return "Not logged in", 401


@app.route("/search")
def search():
    if "username" not in session:
        return "Please log in first", 401
    q = request.args.get("q", "")
    sql = f"SELECT title, body FROM notes WHERE owner = '{session['username']}' AND title LIKE '%{q}%'"
    rows = get_db().execute(sql).fetchall()
    html = f"<h2>Results for: {q}</h2>"
    for row in rows:
        html += f"<h3>{row['title']}</h3><p>{row['body']}</p>"
    return html


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    count_flag = "-n" if os.name == "nt" else "-c"
    result = subprocess.run("ping " + count_flag + " 1 " + host, shell=True, capture_output=True, text=True)
    return "<pre>" + result.stdout + result.stderr + "</pre>"


@app.route("/download")
def download():
    name = request.args.get("file", "welcome.txt")
    return send_file(os.path.join(FILES_DIR, name))


@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        return "Please log in first", 401
    user = get_db().execute("SELECT username, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return "No such user", 404
    return f"{user['username']} ({user['role']}) - {user['email']}"


@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return "Admins only", 403
    users = get_db().execute("SELECT username, email, role FROM users").fetchall()
    return "<h2>All users</h2>" + "<br>".join(f"{u['username']} - {u['email']} - {u['role']}" for u in users)


if __name__ == "__main__":
    init_files()
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
