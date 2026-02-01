from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3, bcrypt, re

app = Flask(__name__)
app.secret_key = "secure_project_secret_key"

# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)
    conn.commit()
    conn.close()

# ---------------- USER CLASS ----------------
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    conn.close()
    if user:
        return User(*user)
    return None

# ---------------- PASSWORD POLICY ----------------
def strong_password(pw):
    return (
        len(pw) >= 8 and
        re.search(r"[A-Z]", pw) and
        re.search(r"[0-9]", pw) and
        re.search(r"[@$!%*?&]", pw)
    )

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        if not strong_password(password):
            flash("Password must be strong (8 chars, uppercase, number, special char)")
            return redirect("/register")

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO users VALUES (NULL,?,?,?)",
                        (username, hashed_pw, role))
            conn.commit()
            conn.close()
            flash("Registration successful")
            return redirect("/login")
        except:
            flash("Username already exists")
            return redirect("/register")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user[2]):
            login_user(User(user[0], user[1], user[3]))
            return redirect("/dashboard")
        else:
            flash("Invalid credentials")
            return redirect("/login")

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        return "Access Denied", 403
    return render_template("admin.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out securely")
    return redirect("/login")

# ---------------- RUN ----------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)