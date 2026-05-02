from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import os
import time

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-key")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False
)
csrf = CSRFProtect(app)
MAX_ATTEMPTS = 3
LOCK_TIME = 60
# ── Encryption ─────────────────────────────────────────────────────────────────
KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

cipher = Fernet(load_or_create_key())

def encrypt(plaintext: str) -> str:
    return cipher.encrypt(plaintext.encode()).decode()

def decrypt(ciphertext: str) -> str:
    return cipher.decrypt(ciphertext.encode()).decode()

# ── Database ───────────────────────────────────────────────────────────────────
DB = "portal.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS grades (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            course    TEXT    NOT NULL,
            grade_enc TEXT    NOT NULL,
            notes_enc TEXT    NOT NULL,
            date      TEXT    NOT NULL DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    existing = conn.execute(
        "SELECT id FROM users WHERE username='admin'"
    ).fetchone()

    # ONLY create admin if not exists
    if not existing:
        admin_password = os.environ.get("ADMIN_PASSWORD")

        if not admin_password:
            raise RuntimeError("ADMIN_PASSWORD environment variable is required.")

        hashed = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()

        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", hashed, "admin")
        )

    conn.commit()
    conn.close()

# ── Decorators ─────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Access denied. Admins only.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        # Basic empty check
        if not username or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        # Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")

        if " " in password:
            flash("Password cannot contain spaces.", "danger")
            return render_template("register.html")

        if not any(char.isupper() for char in password):
            flash("Password must contain at least one uppercase letter.", "danger")
            return render_template("register.html")

        if not any(char.islower() for char in password):
            flash("Password must contain at least one lowercase letter.", "danger")
            return render_template("register.html")

        if not any(char.isdigit() for char in password):
            flash("Password must contain at least one number.", "danger")
            return render_template("register.html")
        if not any(char in "!@#$%^&*()" for char in password):
            flash("Password must contain at least one special character (!@#$%^&*).", "danger")
            return render_template("register.html")

        # Hash password
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed, "user")
            )
            conn.commit()
            conn.close()

            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if "login_attempts" not in session:
            session["login_attempts"] = 0
            session["last_attempt"] = 0

        if session["login_attempts"] >= MAX_ATTEMPTS:
            if time.time() - session["last_attempt"] < LOCK_TIME:
                flash(f"Too many attempts. Please wait {LOCK_TIME} seconds.", "danger")
                return render_template("login.html")
            else:
                session["login_attempts"] = 0

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            session["login_attempts"] = 0

            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("dashboard"))

        session["login_attempts"] += 1
        session["last_attempt"] = time.time()

        flash("Invalid username or password.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()

        if not bcrypt.checkpw(current_password.encode(), user["password"].encode()):
            conn.close()
            flash("Current password is incorrect.", "danger")
            return render_template("change_password.html")

        if new_password != confirm_password:
            conn.close()
            flash("New passwords do not match.", "danger")
            return render_template("change_password.html")

        if len(new_password) < 8:
            conn.close()
            flash("New password must be at least 8 characters.", "danger")
            return render_template("change_password.html")

        if " " in new_password:
            conn.close()
            flash("New password cannot contain spaces.", "danger")
            return render_template("change_password.html")

        if not any(char.isupper() for char in new_password):
            conn.close()
            flash("New password must contain at least one uppercase letter.", "danger")
            return render_template("change_password.html")

        if not any(char.islower() for char in new_password):
            conn.close()
            flash("New password must contain at least one lowercase letter.", "danger")
            return render_template("change_password.html")

        if not any(char.isdigit() for char in new_password):
            conn.close()
            flash("New password must contain at least one number.", "danger")
            return render_template("change_password.html")

        if not any(char in "!@#$%^&*()" for char in new_password):
            conn.close()
            flash("New password must contain at least one special character.", "danger")
            return render_template("change_password.html")

        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hashed, session["user_id"])
        )
        conn.commit()
        conn.close()

        flash("Password changed successfully. Please log in again.", "success")
        session.clear()
        return redirect(url_for("login"))

    return render_template("change_password.html")

# ── Student dashboard — READ ONLY ──────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("admin"))

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM grades WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()

    grades = []
    for r in rows:
        grades.append({
            "course": r["course"],
            "grade":  decrypt(r["grade_enc"]),
            "notes":  decrypt(r["notes_enc"]),
            "date":   r["date"],
        })
    return render_template("dashboard.html", grades=grades)

# ── Admin panel ────────────────────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin():
    conn = get_db()
    students = conn.execute(
        "SELECT id, username FROM users WHERE role = 'user' ORDER BY username"
    ).fetchall()
    all_grades = conn.execute("""
        SELECT g.id, u.username, g.course, g.grade_enc, g.notes_enc, g.date
        FROM grades g
        JOIN users u ON g.user_id = u.id
        ORDER BY u.username, g.course
    """).fetchall()
    conn.close()

    grade_list = []
    for g in all_grades:
        grade_list.append({
            "id":       g["id"],
            "username": g["username"],
            "course":   g["course"],
            "grade":    decrypt(g["grade_enc"]),
            "notes":    decrypt(g["notes_enc"]),
            "date":     g["date"],
        })
    return render_template("admin.html", students=students, grades=grade_list)

# ── Admin assigns a grade ──────────────────────────────────────────────────────
@app.route("/admin/assign_grade", methods=["POST"])
@admin_required
def assign_grade():
    user_id = request.form["user_id"]
    course  = request.form["course"].strip()
    grade   = request.form["grade"].strip()
    notes   = request.form["notes"].strip()
    date    = request.form["date"].strip()
    # Course length validation
    if len(course) > 50:
      flash("Course name is too long (max 50 characters).", "danger")
      return redirect(url_for("admin"))

    if not user_id or not course or not grade or not date:
        flash("Student, course, grade and date are all required.", "danger")
        return redirect(url_for("admin"))

    conn = get_db()
    student = conn.execute(
        "SELECT id FROM users WHERE id = ? AND role = 'user'", (user_id,)
    ).fetchone()
    if not student:
        flash("Invalid student selected.", "danger")
        conn.close()
        return redirect(url_for("admin"))

    conn.execute(
        "INSERT INTO grades (user_id, course, grade_enc, notes_enc, date) VALUES (?, ?, ?, ?, ?)",
        (user_id, course, encrypt(grade), encrypt(notes or "—"), date)
    )
    conn.commit()
    conn.close()
    flash("Grade assigned and encrypted successfully.", "success")
    return redirect(url_for("admin"))

# ── Admin edits a grade ────────────────────────────────────────────────────────
@app.route("/admin/edit_grade/<int:grade_id>", methods=["POST"])
@admin_required
def edit_grade(grade_id):
    grade = request.form["grade"].strip()
    notes = request.form["notes"].strip()
    date  = request.form["date"].strip()

    if not grade or not date:
        flash("Grade and date cannot be empty.", "danger")
        return redirect(url_for("admin"))

    conn = get_db()
    conn.execute(
        "UPDATE grades SET grade_enc = ?, notes_enc = ?, date = ? WHERE id = ?",
        (encrypt(grade), encrypt(notes or "—"), date, grade_id)
    )
    conn.commit()
    conn.close()
    flash("Grade updated successfully.", "success")
    return redirect(url_for("admin"))

# ── Admin deletes a grade ──────────────────────────────────────────────────────
@app.route("/admin/delete_grade/<int:grade_id>", methods=["POST"])
@admin_required
def delete_grade(grade_id):
    conn = get_db()
    conn.execute("DELETE FROM grades WHERE id = ?", (grade_id,))
    conn.commit()
    conn.close()
    flash("Grade deleted.", "info")
    return redirect(url_for("admin"))

# ── Admin deletes a student ────────────────────────────────────────────────────
@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    conn = get_db()
    user = conn.execute(
        "SELECT username, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user and user["role"] == "admin":
        flash("Cannot delete the admin account.", "danger")
    elif user:
        conn.execute("DELETE FROM grades WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash(f"Student '{user['username']}' deleted.", "info")
    conn.close()
    return redirect(url_for("admin"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)