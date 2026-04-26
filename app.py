from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ── Encryption Key ─────────────────────────────────────────────────────────────
KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

FERNET_KEY = load_or_create_key()
cipher = Fernet(FERNET_KEY)

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
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            course     TEXT    NOT NULL,
            grade_enc  TEXT    NOT NULL,
            notes_enc  TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", hashed, "admin")
        )
        conn.commit()
    conn.close()

# ── Access Control Decorators ──────────────────────────────────────────────────
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
        if not username or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed, "user")
            )
            conn.commit()
            conn.close()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM grades WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()
    grades = []
    for r in rows:
        grades.append({
            "id":     r["id"],
            "course": r["course"],
            "grade":  decrypt(r["grade_enc"]),
            "notes":  decrypt(r["notes_enc"]),
        })
    return render_template("dashboard.html", grades=grades)

@app.route("/add_grade", methods=["POST"])
@login_required
def add_grade():
    course = request.form["course"].strip()
    grade  = request.form["grade"].strip()
    notes  = request.form["notes"].strip()
    if not course or not grade:
        flash("Course and grade are required.", "danger")
        return redirect(url_for("dashboard"))
    conn = get_db()
    conn.execute(
        "INSERT INTO grades (user_id, course, grade_enc, notes_enc) VALUES (?, ?, ?, ?)",
        (session["user_id"], course, encrypt(grade), encrypt(notes or "N/A"))
    )
    conn.commit()
    conn.close()
    flash("Grade added and encrypted successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/delete_grade/<int:grade_id>", methods=["POST"])
@login_required
def delete_grade(grade_id):
    conn = get_db()
    row = conn.execute(
        "SELECT user_id FROM grades WHERE id = ?", (grade_id,)
    ).fetchone()
    if row and row["user_id"] == session["user_id"]:
        conn.execute("DELETE FROM grades WHERE id = ?", (grade_id,))
        conn.commit()
        flash("Grade deleted.", "info")
    else:
        flash("Unauthorized action.", "danger")
    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/admin")
@admin_required
def admin():
    conn = get_db()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    all_grades = conn.execute("""
        SELECT g.id, u.username, g.course, g.grade_enc, g.notes_enc
        FROM grades g JOIN users u ON g.user_id = u.id
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
        })
    return render_template("admin.html", users=users, grades=grade_list)

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
    if user and user["role"] == "admin":
        flash("Cannot delete admin account.", "danger")
    elif user:
        conn.execute("DELETE FROM grades WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        flash("User deleted.", "info")
    conn.close()
    return redirect(url_for("admin"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)