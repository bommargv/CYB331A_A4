import os
import sqlite3
from functools import wraps

from flask import (
    Flask, g, redirect, render_template, request, session, url_for, flash
)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


# ---------------------------------------------------------------- helpers
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not (3 <= len(username) <= 30):
            error = "Username must be 3-30 characters."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."

        if error is None:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "That username is already taken."
            else:
                flash("Account created. You can log in now.", "success")
                return redirect(url_for("login"))

        flash(error, "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Same message for bad username or bad password
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------- templates
# Kept inline so the whole app is one file. Move to a templates/ folder
# and delete this block if you'd rather have separate files.
app.jinja_loader = DictLoader({
    "base.html": """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Flask Auth{% endblock %}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 380px; margin: 4rem auto; padding: 0 1rem; }
    form { display: flex; flex-direction: column; gap: .75rem; }
    input, button { padding: .6rem; font-size: 1rem; }
    button { cursor: pointer; }
    .flash { padding: .6rem; border-radius: 4px; margin-bottom: .75rem; }
    .error { background: #fde8e8; color: #9b1c1c; }
    .success { background: #e6f4ea; color: #1e6b34; }
  </style>
</head>
<body>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}
      <div class="flash {{ category }}">{{ message }}</div>
    {% endfor %}
  {% endwith %}
  {% block content %}{% endblock %}
</body>
</html>
""",
    "register.html": """
{% extends "base.html" %}
{% block title %}Register{% endblock %}
{% block content %}
  <h2>Register</h2>
  <form method="post">
    <input name="username" placeholder="Username" required minlength="3" maxlength="30" autofocus>
    <input name="password" type="password" placeholder="Password (8+ chars)" required minlength="8">
    <input name="confirm" type="password" placeholder="Confirm password" required>
    <button type="submit">Create account</button>
  </form>
  <p>Already have an account? <a href="{{ url_for('login') }}">Log in</a></p>
{% endblock %}
""",
    "login.html": """
{% extends "base.html" %}
{% block title %}Log in{% endblock %}
{% block content %}
  <h2>Log in</h2>
  <form method="post">
    <input name="username" placeholder="Username" required autofocus>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Log in</button>
  </form>
  <p>No account? <a href="{{ url_for('register') }}">Register</a></p>
{% endblock %}
""",
    "dashboard.html": """
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
  <h2>Welcome, {{ username }}!</h2>
  <p>You are logged in.</p>
  <p><a href="{{ url_for('logout') }}">Log out</a></p>
{% endblock %}
""",
})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
