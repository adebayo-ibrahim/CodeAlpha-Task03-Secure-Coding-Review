# Secure Coding Review: NoteVault (Python / Flask)

CodeAlpha Cyber Security Internship, Task 3.

| | |
|---|---|
| Application | NoteVault, a small notes web app (Python 3, Flask, SQLite) |
| Code reviewed | `vulnerable_app.py` (about 170 lines, one file) |
| Date | 19 November 2026 |
| Methods | Static analysis with Bandit, manual code review, dynamic testing with real attack payloads |
| Result | 12 findings: 3 Critical, 5 High, 3 Medium, 1 Low. All of them are fixed in `secure_app.py` |

NoteVault was written for this exercise and contains common real-world mistakes on purpose, so that a review has something to find. It must never be deployed.

## 1. Summary

A visitor with no account can run commands on the server (F3, F4) and log in as the admin (F1, F5). A normal user can read every password hash (F2), read other users' data (F9) and download the application's source code (F7). The passwords are hashed with unsalted MD5, so stolen hashes are cracked almost instantly (F6).

Most of the findings share two root causes:

- **Untrusted input reaches an interpreter.** User input is pasted into SQL (F1, F2), a shell command (F3), a pickle loader (F4), a file path (F7) and HTML (F8).
- **The server trusts the client.** The admin role lives in a cookie that anyone with the signing key can forge (F5), and several routes never check who is asking (F9).

`secure_app.py` fixes every finding. `test_security.py` replays the same attacks against both versions: all of them work on `vulnerable_app.py` and none works on `secure_app.py`, while normal use (login, search, profile, download, admin page) keeps working.

## 2. Scope and method

**Scope.** All routes of NoteVault: login, notes search, ping tool, file download, profile page, admin page, plus its configuration and start-up code.

**Method.**

1. **Static analysis.** Bandit, a security linter for Python, scans the source without running it (`bandit vulnerable_app.py`).
2. **Manual review.** Reading the code against the OWASP Top 10 (2021): injection, authentication, session handling, access control, cryptography and secrets, configuration, error handling.
3. **Dynamic testing.** `test_security.py` sends the attack payloads to the running application code and records whether each one works. Both apps were also run as real web servers and the main attacks were repeated with `curl`.

**Severity scale** (a judgement from impact and ease of exploitation, not a formal CVSS score):

| Level | Meaning |
|---|---|
| Critical | Someone with no account can take over the app or the server |
| High | Serious data exposure or takeover, needs a small extra step (a login, or access to the source code) |
| Medium | Needs another weakness or a user action to cause real damage |
| Low | Weakens the defence in depth |

## 3. Findings at a glance

| ID | Finding | Severity | CWE | OWASP 2021 | Where in `vulnerable_app.py` | Bandit check |
|---|---|---|---|---|---|---|
| F1 | SQL injection in login | Critical | CWE-89 | A03 Injection | line 96 | B608 |
| F2 | SQL injection in note search | High | CWE-89 | A03 Injection | line 125 | B608 |
| F3 | OS command injection in the ping tool | Critical | CWE-78 | A03 Injection | line 137 | B602, B404 |
| F4 | Insecure deserialization (pickle cookie) | Critical | CWE-502 | A08 Software and Data Integrity Failures | lines 104-105, 115 | B301, B403 |
| F5 | Hard-coded secret key and admin password | High | CWE-798 | A07 Identification and Authentication Failures | lines 21-22 | B105 |
| F6 | Passwords hashed with unsalted MD5 | Medium | CWE-327, CWE-916 | A02 Cryptographic Failures | lines 49-50 | B324 |
| F7 | Path traversal in file download | High | CWE-22 | A01 Broken Access Control | line 144 | none |
| F8 | Reflected cross-site scripting (XSS) in search | Medium | CWE-79 | A03 Injection | lines 127-130 | none |
| F9 | Broken access control: IDOR and missing login checks | High | CWE-639, CWE-862 | A01 Broken Access Control | lines 133, 141, 147-154 | none |
| F10 | Debug mode on, listening on all interfaces | High | CWE-489, CWE-1327 | A05 Security Misconfiguration | line 168 | B201, B104 |
| F11 | No protection against password guessing | Medium | CWE-307 | A07 Identification and Authentication Failures | lines 92-106 | none |
| F12 | Missing security headers and cookie flags | Low | CWE-693, CWE-1275 | A05 Security Misconfiguration | lines 26-27 | none |

## 4. Findings in detail

### F1. SQL injection in login (Critical)

`login()` builds its SQL query by pasting the username into a string. The username can therefore change the query itself.

**Proof.** Username `admin' --` with any password returns `Welcome, admin`. The `--` turns the rest of the query, including the password check, into a comment.

**Impact.** Log in as any user, including the admin, without knowing the password.

Vulnerable code (`vulnerable_app.py`, line 96):

```python
query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, hash_password(password))
```

Fix (`secure_app.py`, lines 179-180). The value travels as a parameter, so it can never become SQL. The password is checked in Python against a salted hash:

```python
rows = query("SELECT id, username, password FROM users WHERE username = ?", (username,))
if not rows or not check_password_hash(rows[0]["password"], password):
```

### F2. SQL injection in note search (High)

The search box value and the username are pasted into the SQL text with an f-string.

**Proof.** Logged in as a normal user, the search text `zzz' UNION SELECT username, password FROM users --` returns every username with its password hash in the results page.

**Impact.** A normal account can read data from any table in the database.

Vulnerable code (`vulnerable_app.py`, line 125):

```python
sql = f"SELECT title, body FROM notes WHERE owner = '{session['username']}' AND title LIKE '%{q}%'"
```

Fix (`secure_app.py`, line 200):

```python
rows = query("SELECT title, body FROM notes WHERE owner = ? AND title LIKE ?", (g.user["username"], f"%{q}%"))
```

### F3. OS command injection in the ping tool (Critical)

The host name from the URL is added to a command line that runs through a shell (`shell=True`). The shell treats `;` and `&` as "run another command".

**Proof.** Host `127.0.0.1 & whoami` on Windows, or `127.0.0.1; id` on Linux and macOS: the output of the second command appears in the page. No login is needed.

**Impact.** Running any command on the server as the user that runs the app.

Vulnerable code (`vulnerable_app.py`, line 137):

```python
result = subprocess.run("ping " + count_flag + " 1 " + host, shell=True, capture_output=True, text=True)
```

Fix (`secure_app.py`). Only admins can use the tool, the input must be a valid IP address, no shell is used and the command is a list of separate arguments, so nothing in the input can be read as a command:

```python
@admin_required
def ping():
    try:
        address = str(ipaddress.ip_address(request.args.get("host", "127.0.0.1")))
    except ValueError:
        return "Please enter a valid IP address.", 400
```

```python
command = [ping_program, count_flag, "1", address]
try:
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)  # nosec B603
```

### F4. Insecure deserialization: pickle cookie (Critical)

After login the app stores a `remember` cookie made with `pickle` and later loads it with `pickle.loads`. Pickle is not a data format only: loading a pickle can call any Python function that the data names. The cookie comes from the browser, so the attacker writes it.

**Proof.** A crafted `remember` cookie makes the server run attacker-chosen Python code. `test_security.py` proves it by making the app create a file. No login is needed.

**Impact.** Running any code on the server.

Vulnerable code (`vulnerable_app.py`, lines 104-105 and 115):

```python
remember = base64.b64encode(pickle.dumps({"username": user["username"]}))
response.set_cookie("remember", remember.decode())
```

```python
data = pickle.loads(base64.b64decode(remember))
```

Fix. The `remember` cookie is removed. Login state lives only in Flask's signed session, which holds the user id and nothing else (`secure_app.py`, lines 184-186). The session is cleared first, which also prevents session fixation:

```python
session.clear()
session["user_id"] = rows[0]["id"]
session.permanent = True
```

### F5. Hard-coded secret key and admin password (High)

The key that signs the session cookie and the admin password are written in the source code. The role (`admin` or `user`) is stored inside the session cookie, and `/admin` trusts it.

**Proof.** Using the key from the source, a forged cookie `{user_id: 1, username: admin, role: admin}` opens `/admin`. Logging in with the password `admin123` from the source also works.

**Impact.** Anyone who sees the source code (a public GitHub repository, a leaked backup) can become admin. Once a secret has been committed it must be treated as leaked.

Vulnerable code (`vulnerable_app.py`, lines 21-22):

```python
SECRET_KEY = "notevault-secret-2024"
ADMIN_PASSWORD = "admin123"
```

Fix (`secure_app.py`, lines 30-31). Secrets come from environment variables. If they are not set, a random value is created for each run:

```python
SECRET_KEY = os.environ.get("NOTEVAULT_SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = ADMIN_PASSWORD_FROM_ENV or secrets.token_urlsafe(12)
```

The role is no longer stored in the cookie. The session only holds the user id and the user is read from the database on every request (`secure_app.py`, lines 121-127):

```python
def current_user():
    """The logged-in user, read from the database on every request (the session only holds the id)."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    rows = query("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    return rows[0] if rows else None
```

### F6. Passwords hashed with unsalted MD5 (Medium)

MD5 is fast and has no salt, so two users with the same password get the same hash and attackers test billions of guesses per second or use ready-made tables.

**Proof.** The stored hash of the demo user `alice` is exactly `md5("alice-pass-1")`.

**Impact.** Stolen hashes (see F1 and F2) turn into passwords quickly, and people reuse passwords on other sites.

Vulnerable code (`vulnerable_app.py`, lines 49-50):

```python
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

Fix (`secure_app.py`, lines 94-95). Werkzeug's `generate_password_hash` uses a slow, salted algorithm (scrypt by default). The login check at line 180 uses `check_password_hash`:

```python
db.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
           (username, generate_password_hash(password), email, role))
```

### F7. Path traversal in file download (High)

The file name from the URL is joined to the download folder without any check, so `../` climbs out of the folder.

**Proof.** `/download?file=../vulnerable_app.py` returns the source code of the application. On a real server `../../etc/passwd` works the same way.

**Impact.** Reading any file the app can read: source code, configuration, databases, keys.

Vulnerable code (`vulnerable_app.py`, line 144):

```python
return send_file(os.path.join(FILES_DIR, name))
```

Fix (`secure_app.py`, line 227). `send_from_directory` refuses any path that leaves the folder. `as_attachment=True` makes the browser download the file instead of displaying it:

```python
return send_from_directory(FILES_DIR, name, as_attachment=True)
```

### F8. Reflected cross-site scripting (Medium)

The search text is placed into the page as raw HTML.

**Proof.** `/search?q=<script>alert(1)</script>` comes back unchanged inside the page, so the browser runs the script.

**Impact.** An attacker sends a victim a crafted link; the script then runs with the victim's session (stealing data, acting as the victim).

Vulnerable code (`vulnerable_app.py`, lines 127-130):

```python
html = f"<h2>Results for: {q}</h2>"
for row in rows:
    html += f"<h3>{row['title']}</h3><p>{row['body']}</p>"
return html
```

Fix (`secure_app.py`, line 201). The page is built from a Jinja2 template, which turns `<` into `&lt;` automatically. A `Content-Security-Policy` header (line 115, see F12) adds a second layer:

```python
return render_template_string(RESULTS_TEMPLATE, q=q, rows=rows)
```

### F9. Broken access control: IDOR and missing login checks (High)

- **IDOR (insecure direct object reference).** `/profile/<id>` checks that someone is logged in, but not that the profile belongs to them.
- **Missing authentication.** `/ping` (line 133) and `/download` (line 141) need no login at all.

**Proof.** Logged in as `alice` (id 2), `/profile/1` shows the admin's e-mail address and role. `/ping` and `/download` answer without any login.

**Impact.** Any user can read every other user's data, and anyone can use features meant for staff.

Vulnerable code (`vulnerable_app.py`, lines 147-154):

```python
@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        return "Please log in first", 401
    user = get_db().execute("SELECT username, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return "No such user", 404
    return f"{user['username']} ({user['role']}) - {user['email']}"
```

Fix (`secure_app.py`, lines 230-234). Every route has a `@login_required` or `@admin_required` decorator, and the profile route compares the requested id with the logged-in user:

```python
@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    if user_id != g.user["id"] and g.user["role"] != "admin":
        abort(403)
```

### F10. Debug mode on and listening on all interfaces (High)

The app starts with `debug=True` and `host="0.0.0.0"`. Debug mode shows detailed error pages and turns on Werkzeug's interactive debugger, a Python console in the browser protected only by a PIN. Listening on `0.0.0.0` makes the app reachable from every computer on the network, not only from the developer's machine.

**Proof.** With the app running, `/console` answers with the debugger console page.

**Impact.** Information leaks through error pages. If the PIN is leaked or guessed, the console runs code on the server.

Vulnerable code (`vulnerable_app.py`, line 168):

```python
app.run(host="0.0.0.0", port=5000, debug=True)
```

Fix (`secure_app.py`, line 252). Debug is off and the app listens on the local machine only. In production a proper server (for example gunicorn or waitress) behind HTTPS is used:

```python
app.run(host="127.0.0.1", port=5000, debug=False)
```

### F11. No protection against password guessing (Medium)

`login()` (lines 92-106) accepts unlimited attempts, so a script can try thousands of passwords.

**Proof.** After 8 wrong passwords for `bob`, the correct password still logs in.

**Impact.** Weak passwords are found by brute force.

Fix (`secure_app.py`, lines 177-178, with the helper functions at lines 149-164). After 5 wrong passwords within 5 minutes for the same address and user name, the login answers `429 Too Many Requests`:

```python
if is_locked(key):
    return "Too many failed attempts. Try again in a few minutes.", 429
```

### F12. Missing security headers and cookie flags (Low)

The responses carry none of the headers that make browsers refuse some attacks, and the session cookie has no `SameSite` attribute (Flask's default).

**Proof.** The responses have no `Content-Security-Policy`, `X-Content-Type-Options` or `X-Frame-Options` header, and the `Set-Cookie` header of the login has no `SameSite`.

**Impact.** Cross-site scripting, clickjacking and cross-site request forgery become easier.

Fix (`secure_app.py`, lines 38-44 and 113-118):

```python
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NOTEVAULT_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)
```

```python
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
```

## 5. Static analysis with Bandit: what it finds and what it misses

Run Bandit on both versions and keep the output as evidence:

```text
bandit vulnerable_app.py -f txt -o bandit_vulnerable.txt
bandit secure_app.py -f txt -o bandit_secure.txt
```

Bandit has a check for 7 of the 12 findings:

| Bandit test | Name | Finding |
|---|---|---|
| B608 | hardcoded_sql_expressions | F1, F2 |
| B602 | subprocess_popen_with_shell_equals_true | F3 |
| B404 | blacklist: import of subprocess | F3 |
| B301 | blacklist: pickle | F4 |
| B403 | blacklist: import of pickle | F4 |
| B105 | hardcoded_password_string | F5 |
| B324 | hashlib (weak hash) | F6 |
| B201 | flask_debug_true | F10 |
| B104 | hardcoded_bind_all_interfaces | F10 |

The exact list depends on the Bandit version, so compare it with your own scan.

**Bandit has no check for F7, F8, F9, F11 and F12.** These are design and logic mistakes (a missing check, a missing limit, a missing header) and there is no single dangerous function call for a tool to spot. They were found by manual review and confirmed by the attack tests. This is why a static scan alone is not a security review.

**The fixed version.** Bandit would still warn about two lines in `secure_app.py`: the `subprocess` import (B404) and the `subprocess.run` call (B603). They are accepted on purpose and marked with `# nosec` and a comment, because no shell is used and the input is validated with `ipaddress` first. A `# nosec` mark without a reason should never be accepted in a code review.

## 6. Secure coding recommendations

| Area | Practice | Where it shows in this project |
|---|---|---|
| Injection | Never build SQL, shell commands or HTML by joining strings with user input. Use query parameters, argument lists and auto-escaping templates | F1, F2, F3, F8 |
| Input validation | Check input against what is allowed (an allow-list such as `ipaddress.ip_address`), not against what is forbidden. Reject early | F3 |
| Dangerous functions | Avoid `pickle`, `eval`, `exec` and `shell=True` on data you do not control. Use JSON or a signed session instead | F3, F4 |
| Secrets | Keep keys and passwords out of the code (environment variables, a secret manager). Treat anything that was committed as leaked and rotate it | F5 |
| Passwords | Store only slow, salted hashes (scrypt, bcrypt, argon2). Never MD5 or SHA-1 | F6 |
| Authentication | Limit guesses, regenerate the session at login, keep sessions short, offer multi-factor authentication | F11 |
| Authorization | Deny by default. Check on the server, on every request, who may see this object. Never trust a role or id that the client sends | F5, F9 |
| Files | Never use a user-supplied path directly. Use `send_from_directory` or an allow-list of names | F7 |
| Configuration | Debug off, listen on localhost or behind a reverse proxy, HTTPS, security headers, cookie flags | F10, F12 |
| Errors and logging | Show generic error messages to users, log security events (failed logins, access denied) for the operators | not covered by NoteVault |
| Process | Run Bandit in CI, scan dependencies (`pip-audit`), review code with a checklist, and keep tests that replay the attacks, like `test_security.py` | section 5 |

## 7. Limits of this review and of the fixed version

- The tests prove that specific attacks fail. They do not prove that the app has no other bugs, for example a different SQL injection payload or a flaw nobody looked for.
- The login lockout is kept in memory, so it works for one process only and resets when the app restarts. It can also lock out a real user who is being attacked. A production system needs a shared store (Redis), rate limiting at the proxy or with a library such as Flask-Limiter, and ideally multi-factor authentication.
- There are no CSRF tokens. `SameSite=Lax` covers the only POST form (the login). If state-changing forms are added, add CSRF tokens (for example with Flask-WTF).
- The development server has no HTTPS. Behind TLS, set `NOTEVAULT_HTTPS=1` so the session cookie is marked `Secure`.
- The demo accounts (`alice`, `bob`) have fixed passwords for this exercise only, and the app has no audit log.
- This is a review of one small application written for the exercise. It is not a penetration test of a real system.

## 8. Conclusion

NoteVault shows how a few habits (building queries from strings, running shells and loaders on user input, trusting cookies, skipping server-side checks) combine into a full takeover of an application. Each fix in `secure_app.py` is small: parameterized queries, argument lists, validated input, auto-escaping, slow password hashes, secrets outside the code, and a permission check on every route. Static analysis can flag 7 of the 12 problems quickly; the other 5 need a person who asks "who is allowed to do this?" and "what if the input is hostile?". Both are needed.

## References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE: Common Weakness Enumeration](https://cwe.mitre.org/)
- [Bandit: security linter for Python](https://bandit.readthedocs.io/)
- [Flask: security considerations](https://flask.palletsprojects.com/en/stable/web-security/)
- [Python documentation: pickle (security warning)](https://docs.python.org/3/library/pickle.html)
