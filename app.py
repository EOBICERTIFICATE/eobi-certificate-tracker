import os
import random
import string
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, jsonify
)
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'super_secret_key'

# --- Database setup (SQLite for easy hosting, expandable to Postgres/MySQL) ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eobi_certificates.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Email config ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# --- Login/Password ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

# --- User roles
ROLES = [
    "chairman", "admin", "ddg", "rh", "bts", "officer"
]

# --- Region and B&C mapping (expand as needed) ---
REGIONS_BC_MAP = [
    {"code": "2100", "name": "Multan", "bc": "B&C-2"},
    {"code": "2000", "name": "Muzaffargarh", "bc": "B&C-2"},
    {"code": "2200", "name": "Bahawalpur", "bc": "B&C-2"},
    {"code": "2300", "name": "Rahim Yar Khan", "bc": "B&C-2"},
    {"code": "2400", "name": "Dera Ghazi Khan", "bc": "B&C-2"},
    {"code": "2500", "name": "Layyah", "bc": "B&C-2"},
    {"code": "2600", "name": "Vehari", "bc": "B&C-2"},
    {"code": "2700", "name": "Lodhran", "bc": "B&C-2"},
    {"code": "2800", "name": "Khanewal", "bc": "B&C-2"},
    {"code": "2900", "name": "Pakpattan", "bc": "B&C-2"},
    {"code": "3000", "name": "Sahiwal", "bc": "B&C-2"},
    {"code": "3100", "name": "Okara", "bc": "B&C-2"},
    {"code": "3200", "name": "Kasur", "bc": "B&C-2"},
    {"code": "3300", "name": "Sheikhupura", "bc": "B&C-2"},
    {"code": "3400", "name": "Nankana Sahib", "bc": "B&C-2"},
    {"code": "3500", "name": "Faisalabad", "bc": "B&C-2"},
    {"code": "3600", "name": "Jhang", "bc": "B&C-2"},
    {"code": "3700", "name": "Toba Tek Singh", "bc": "B&C-2"},
    {"code": "3800", "name": "Chiniot", "bc": "B&C-2"},
    # Karachi Sample
    {"code": "100", "name": "Nazimabad", "bc": "B&C-1"},
    {"code": "200", "name": "Karachi East", "bc": "B&C-1"},
    {"code": "300", "name": "Korangi", "bc": "B&C-1"},
    # Add more as needed
]

# --- DB MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), unique=True, nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=True)
    name = db.Column(db.String(64), nullable=True)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), nullable=False)
    region_code = db.Column(db.String(8), nullable=True)
    beat_code = db.Column(db.String(8), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def get_id(self):
        return self.username

class Region(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    bc = db.Column(db.String(8), nullable=True)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tracking_id = db.Column(db.String(32), unique=True, nullable=False)
    fir = db.Column(db.String(32), nullable=True)
    claimant_name = db.Column(db.String(64), nullable=False)
    cnic = db.Column(db.String(15), nullable=False)
    eobi_no = db.Column(db.String(15), nullable=False)
    employer = db.Column(db.String(128), nullable=False)
    beat_code = db.Column(db.String(8), nullable=True)
    region_code = db.Column(db.String(8), nullable=False)
    assigned_officer = db.Column(db.String(16), nullable=True)
    file_name = db.Column(db.String(128), nullable=True)
    status = db.Column(db.String(32), default="pending")
    days_pending = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    cross_verified = db.Column(db.Boolean, default=False)
    history = db.Column(db.Text, nullable=True)  # for JSON or string list of assignments

# --- UTILS ---

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def random_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def gen_tracking_id(cnic, eobi_no, region, beat):
    rand = ''.join(random.choices(string.digits, k=3))
    return f"{region}-{beat}-{cnic[-4:]}-{eobi_no[-4:]}-{rand}"

def send_login_email(email, username, password):
    try:
        msg = Message('EOBI Portal Login Created',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"""Your EOBI Portal Login:

Username: {username}
Password: {password}

Login URL: [your URL here]

Please change your password after login."""
        mail.send(msg)
    except Exception as e:
        print("Mail error:", e)

@login_manager.user_loader
def load_user(username):
    return User.query.filter_by(username=username).first()

# --- APP SETUP: RUNS ONLY ONCE AFTER SERVER START ---
setup_done = False

@app.before_request
def setup():
    global setup_done
    if not setup_done:
        db.create_all()
        # --- Add region mapping on first run ---
        for reg in REGIONS_BC_MAP:
            if not Region.query.filter_by(code=reg['code']).first():
                region = Region(code=reg['code'], name=reg['name'], bc=reg['bc'])
                db.session.add(region)
        db.session.commit()

        # --- Add default chairman/admin if not exists ---
        if not User.query.filter_by(username='mainadmin').first():
            pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
            user = User(username='mainadmin', password=pw, role='admin', name='Main Admin', must_change_password=True)
            db.session.add(user)
        if not User.query.filter_by(username='chairman').first():
            pw = bcrypt.generate_password_hash('chairman123').decode('utf-8')
            user = User(username='chairman', password=pw, role='chairman', name='Chairman', must_change_password=True)
            db.session.add(user)
        db.session.commit()
        setup_done = True

# --- ROUTES ---

@app.route("/")
@login_required
def dashboard():
    user = current_user
    certs = Certificate.query
    if user.role == "chairman":
        certs = certs.all()
    elif user.role == "admin":
        certs = certs.all()
    elif user.role in ["ddg", "rh", "bts"]:
        certs = certs.filter_by(region_code=user.region_code).all()
    else:  # officer
        certs = certs.filter_by(assigned_officer=user.username).all()
    pending = [c for c in certs if c.status == "pending"]
    completed = [c for c in certs if c.status == "completed"]
    for c in certs:
        c.days_pending = (datetime.utcnow() - c.created_at).days
    return render_template("dashboard.html", user=user, pending=pending, completed=completed, certs=certs)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.must_change_password:
                return redirect(url_for('change_password'))
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        pw1 = request.form['password1']
        pw2 = request.form['password2']
        if pw1 != pw2:
            flash("Passwords do not match.")
        elif len(pw1) < 6:
            flash("Password must be at least 6 characters.")
        else:
            user = current_user
            user.password = bcrypt.generate_password_hash(pw1).decode('utf-8')
            user.must_change_password = False
            db.session.commit()
            flash("Password changed successfully!")
            return redirect(url_for('dashboard'))
    return render_template("change_password.html")

# --- ADD YOUR OTHER ROUTES HERE ---

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
