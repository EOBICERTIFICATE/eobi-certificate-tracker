import os
import random
import string
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory
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

# --- Database setup ---
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

# --- Full Region codes and B&C mapping ---
REGIONS_BC_MAP = [
    {"code": "100", "name": "Nazimabad", "bc": "B&C-1"},
    {"code": "200", "name": "Karimabad", "bc": "B&C-1"},
    {"code": "400", "name": "City", "bc": "B&C-1"},
    {"code": "500", "name": "West Wharf", "bc": "B&C-1"},
    {"code": "600", "name": "Karachi Central", "bc": "B&C-1"},
    {"code": "800", "name": "Korangi", "bc": "B&C-1"},
    {"code": "900", "name": "Bin Qasim", "bc": "B&C-1"},
    {"code": "1000", "name": "Kotri", "bc": "B&C-1"},
    {"code": "1100", "name": "Hyderabad", "bc": "B&C-1"},
    {"code": "1600", "name": "Sukkur", "bc": "B&C-1"},
    {"code": "1700", "name": "Larkana", "bc": "B&C-1"},
    {"code": "1900", "name": "Rahim Yar Khan", "bc": "B&C-2"},
    {"code": "2000", "name": "Muzaffargarh", "bc": "B&C-2"},
    {"code": "2100", "name": "Multan", "bc": "B&C-2"},
    {"code": "2200", "name": "Sahiwal", "bc": "B&C-2"},
    {"code": "2400", "name": "Bahawalpur", "bc": "B&C-2"},
    {"code": "2500", "name": "Faisalabad Central", "bc": "B&C-2"},
    {"code": "2600", "name": "Faisalabad South", "bc": "B&C-2"},
    {"code": "2700", "name": "Faisalabad North", "bc": "B&C-2"},
    {"code": "2800", "name": "Sargodha", "bc": "B&C-2"},
    {"code": "3100", "name": "Lahore South", "bc": "B&C-3"},
    {"code": "3200", "name": "Mangamandi", "bc": "B&C-3"},
    {"code": "3300", "name": "Lahore Central", "bc": "B&C-3"},
    {"code": "3500", "name": "Shahdara", "bc": "B&C-3"},
    {"code": "3600", "name": "Lahore North", "bc": "B&C-3"},
    {"code": "3700", "name": "Sheikhupura", "bc": "B&C-3"},
    {"code": "4100", "name": "Gujranwala", "bc": "B&C-3"},
    {"code": "4200", "name": "Gujrat", "bc": "B&C-3"},
    {"code": "4300", "name": "Sialkot", "bc": "B&C-3"},
    {"code": "4400", "name": "Jehlum", "bc": "B&C-3"},
    {"code": "4600", "name": "Rawalpindi", "bc": "B&C-3"},
    {"code": "4700", "name": "Islamabad West", "bc": "B&C-3"},
    {"code": "4800", "name": "Hasanabdal", "bc": "B&C-3"},
    {"code": "5100", "name": "Peshawar", "bc": "B&C-3"},
    {"code": "5200", "name": "Mardan", "bc": "B&C-3"},
    {"code": "5300", "name": "Abbottabad", "bc": "B&C-3"},
    {"code": "5400", "name": "Gilgit", "bc": "B&C-3"},
    {"code": "6100", "name": "Quetta", "bc": "B&C-3"},
    {"code": "6900", "name": "Hub", "bc": "B&C-3"},
    {"code": "4900", "name": "Islamabad East", "bc": "B&C-3"},
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
    personal_no = db.Column(db.String(6), nullable=True)  # Officer's 6-digit code

    def get_id(self):
        return self.username

class Region(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    bc = db.Column(db.String(16), nullable=True)

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
    history = db.Column(db.Text, nullable=True)

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

# --- INITIALIZATION ---

@app.before_first_request
def setup():
    db.create_all()
    for reg in REGIONS_BC_MAP:
        if not Region.query.filter_by(code=reg['code']).first():
            region = Region(code=reg['code'], name=reg['name'], bc=reg['bc'])
            db.session.add(region)
    db.session.commit()
    if not User.query.filter_by(username='mainadmin').first():
        pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
        user = User(username='mainadmin', password=pw, role='admin', name='Main Admin', must_change_password=True)
        db.session.add(user)
    if not User.query.filter_by(username='chairman').first():
        pw = bcrypt.generate_password_hash('chairman123').decode('utf-8')
        user = User(username='chairman', password=pw, role='chairman', name='Chairman', must_change_password=True)
        db.session.add(user)
    db.session.commit()

# --- ROUTES ---

@app.route("/")
@login_required
def dashboard():
    user = current_user
    certs = Certificate.query
    if user.role == "chairman" or user.role == "admin":
        certs = certs.all()
    elif user.role in ["bts"]:
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

@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == "__main__":
    app.run(debug=True)
