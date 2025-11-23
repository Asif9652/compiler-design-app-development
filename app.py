# app.py
"""
Flask app with ML model integration for improved attack detection.
Uses model.pkl if present (scikit-learn model), otherwise uses a safe fallback model.
Records login attempts in Log table; detected attacks stored in Attack table.
"""

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import os, datetime, json, re, pickle
from pathlib import Path

# -------------------------
# Config
# -------------------------
APP_DB = "cyberattack.db"
MODEL_PATH = Path("model.pkl")

app = Flask(__name__)
app.config["SECRET_KEY"] = "change_this_to_a_random_secret_please"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{APP_DB}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------
# Models
# -------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # 'user' or 'admin'

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username_attempt = db.Column(db.String(120))
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    raw_log = db.Column(db.Text)
    parsed_log = db.Column(db.Text)
    attack_type = db.Column(db.String(120))
    is_attack = db.Column(db.Boolean, default=False)


class Attack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer)
    username = db.Column(db.String(120))
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime)
    attack_type = db.Column(db.String(120))
    raw_log = db.Column(db.Text)
    parsed_log = db.Column(db.Text)


# -------------------------
# Flask-Login loader
# -------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------------
# ML model loading + fallback
# -------------------------
model = None

class SimpleLogModel:
    """Fallback rule-based model that's pickle-friendly."""
    def predict(self, X):
        out = []
        for f in X:
            try:
                total_len, user_len, pw_len, digits, special, has_sql, failed_kw = f
            except Exception:
                out.append(0)
                continue
            score = 0
            score += (1 if has_sql else 0) * 3
            score += (1 if failed_kw else 0) * 2
            score += (1 if pw_len < 5 else 0)
            score += (1 if special > 2 else 0)
            out.append(1 if score >= 2 else 0)
        return out

def load_model():
    global model
    if MODEL_PATH.exists():
        try:
            with MODEL_PATH.open("rb") as fr:
                model_obj = pickle.load(fr)
            model = model_obj
            print("Loaded model.pkl")
            return
        except Exception as e:
            print("Failed to load model.pkl — using fallback model. Error:", e)
    model = SimpleLogModel()
    print("Using fallback SimpleLogModel (no model.pkl).")

load_model()

def model_predict_featurevector(feature_vector):
    global model
    if model is None:
        return None
    try:
        res = model.predict([feature_vector])
        if res and len(res) > 0:
            return int(res[0])
    except Exception as e:
        print("Model prediction error:", e)
    return None

# -------------------------
# Feature extraction (must match create_model.py)
# -------------------------
def extract_features_for_model(username_input: str, password_input: str):
    s = (username_input or "") + " " + (password_input or "")
    total_len = len(s)
    user_len = len(username_input or "")
    pw_len = len(password_input or "")
    digits = sum(ch.isdigit() for ch in s)
    special = sum(1 for ch in s if not ch.isalnum() and not ch.isspace())
    lower = s.lower()
    sql_keywords = ["or 1=1","union select","drop table","select ","insert ","delete ","union"]
    has_sql = int(any(kw in lower for kw in sql_keywords))
    failed_kw = int(any(w in lower for w in ["fail","failed","wrong","invalid"]))
    return [total_len, user_len, pw_len, digits, special, has_sql, failed_kw]


# -------------------------
# Detection helpers + tokenizer
# -------------------------
failed_login_attempts = {}   # { ip: count }  (in-memory)

SQL_KEYWORDS = [
    "or 1=1", "union select", "drop table", "select ", "insert ", "delete ",
    "--", ";", "/*", "*/", "exec(", "information_schema", "concat("
]

def detect_sql(payload_lower: str):
    for kw in SQL_KEYWORDS:
        if kw in payload_lower:
            return True, kw
    return False, None

def analyze_login_attempt(username_input: str, password_input: str):
    s = (username_input or "") + " " + (password_input or "")
    s = s.lower()
    has_sql, matched = detect_sql(s)
    if has_sql:
        return True, "SQL Injection"
    if password_input and password_input.lower() in ("123456","password","admin","qwerty"):
        return True, "Brute Force"
    return False, "Normal user"

def tokenize_log(raw_log_str: str, username: str, ip: str, request_obj):
    ua = request_obj.headers.get("User-Agent", "")
    tokens = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ip": ip,
        "username": username,
        "user_agent": ua,
        "message_summary": raw_log_str[:400],
        "contains_digits": bool(re.search(r"\d", raw_log_str)),
        "word_count": len(raw_log_str.split())
    }
    return json.dumps(tokens, ensure_ascii=False)


# -------------------------
# Recording helpers
# -------------------------
def record_log_and_attack(username_attempt, ip, raw_log, parsed_json, attack_type, is_attack):
    log_entry = Log(
        username_attempt=username_attempt,
        ip_address=ip,
        raw_log=raw_log,
        parsed_log=parsed_json,
        attack_type=attack_type,
        is_attack=bool(is_attack)
    )
    db.session.add(log_entry)
    db.session.commit()

    if is_attack:
        att = Attack(
            log_id=log_entry.id,
            username=username_attempt,
            ip_address=ip,
            timestamp=log_entry.timestamp,
            attack_type=attack_type,
            raw_log=raw_log,
            parsed_log=parsed_json
        )
        db.session.add(att)
        db.session.commit()


# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=("GET","POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        admin_code = request.form.get("admin_code","").strip()
        if not username or not password:
            flash("Username and password required", "warning")
            return redirect(url_for("register"))
        role = "admin" if admin_code == "5768" else "user"
        try:
            u = User(username=username, role=role)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            flash("Username already exists. Choose another.", "warning")
            return redirect(url_for("register"))
    return render_template("register.html")


@app.route("/login", methods=("GET","POST"))
def login():
    ip = request.remote_addr or "0.0.0.0"
    if request.method == "POST":
        username_input = request.form.get("username","").strip()
        password_input = request.form.get("password","")

        raw_summary = f"LoginAttempt user={username_input} ip={ip} password_length={len(password_input)}"

        # signature detection
        sig_is_attack, sig_type = analyze_login_attempt(username_input, password_input)

        # lookup user and check password
        user = User.query.filter_by(username=username_input).first()
        login_success = False
        if user and user.check_password(password_input):
            login_success = True

        # model prediction (priority)
        features = extract_features_for_model(username_input, password_input)
        model_pred = model_predict_featurevector(features)  # 1 => attack, 0 => normal, None => no decision

        # decide final outcome combining model, signature, and counters
        final_is_attack = False
        final_attack_type = "Normal user"

        if model_pred == 1:
            final_is_attack = True
            final_attack_type = "Model: Attack"
        elif sig_is_attack:
            final_is_attack = True
            final_attack_type = sig_type
        else:
            if not login_success:
                # increment failed count for this IP
                failed_login_attempts[ip] = failed_login_attempts.get(ip, 0) + 1
                if failed_login_attempts[ip] >= 3:
                    final_is_attack = True
                    final_attack_type = "Brute Force"
                else:
                    final_is_attack = False
                    final_attack_type = "Failed login"
            else:
                # successful login
                if ip in failed_login_attempts:
                    del failed_login_attempts[ip]
                final_is_attack = False
                final_attack_type = "Normal user"

        parsed = tokenize_log(raw_summary + (" => SUCCESS" if login_success else " => FAILED"), username_input, ip, request)
        record_log_and_attack(username_input, ip, raw_summary + (" => SUCCESS" if login_success else " => FAILED"),
                              parsed, final_attack_type, final_is_attack)

        # post-login behavior
        if login_success:
            login_user(user)
            if user.role == "admin":
                flash("Admin logged in", "success")
                return redirect(url_for("admin_dashboard"))
            else:
                flash("Logged in (user). You can logout.", "success")
                return redirect(url_for("user_page"))
        else:
            flash(f"Login failed ({final_attack_type}). Attempt recorded.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/user")
@login_required
def user_page():
    my_logs = Log.query.filter_by(username_attempt=current_user.username).order_by(Log.timestamp.desc()).limit(20).all()
    return render_template("user.html", logs=my_logs)


@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Admin access only", "danger")
        return redirect(url_for("user_page"))
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    attacks = Attack.query.order_by(Attack.timestamp.desc()).all()
    return render_template("admin_dashboard.html", logs=logs, attacks=attacks)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("index"))


# -------------------------
# DB create + default admin
# -------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        try:
            admin = User(username="admin", role="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
            print("Default admin created: admin / admin123")
        except IntegrityError:
            db.session.rollback()

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)
