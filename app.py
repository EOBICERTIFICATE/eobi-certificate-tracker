import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from flask_bcrypt import Bcrypt

# --- Flask app config ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'super_secret_key'

# --- Database config ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eobi_certificates.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---- Region mapping (from your list!) ----
REGIONS_BC_MAP = [
    # B&C-1
    {"code": "6900", "name": "Hub", "bc": "B&C-1"},
    {"code": "6100", "name": "Quetta", "bc": "B&C-1"},
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
    # B&C-2
    {"code": "1900", "name": "Rahim Yar Khan", "bc": "B&C-2"},
    {"code": "2000", "name": "Muzaffargarh", "bc": "B&C-2"},
    {"code": "2100", "name": "Multan", "bc": "B&C-2"},
    {"code": "2200", "name": "Sahiwal", "bc": "B&C-2"},
    {"code": "2400", "name": "Bahawalpur", "bc": "B&C-2"},
    {"code": "3100", "name": "Lahore South", "bc": "B&C-2"},
    {"code": "3200", "name": "Mangamandi", "bc": "B&C-2"},
    {"code": "3300", "name": "Lahore Central", "bc": "B&C-2"},
    {"code": "3500", "name": "Shahdara", "bc": "B&C-2"},
    {"code": "3600", "name": "Lahore North", "bc": "B&C-2"},
    {"code": "3700", "name": "Sheikhupura", "bc": "B&C-2"},
    {"code": "4100", "name": "Gujranwala", "bc": "B&C-2"},
    {"code": "4200", "name": "Gujrat", "bc": "B&C-2"},
    {"code": "4300", "name": "Sialkot", "bc": "B&C-2"},
    # B&C-1
    {"code": "2500", "name": "Faisalabad Central", "bc": "B&C-1"},
    {"code": "2600", "name": "Faisalabad South", "bc": "B&C-1"},
    {"code": "2700", "name": "Faisalabad North", "bc": "B&C-1"},
    {"code": "2800", "name": "Sargodha", "bc": "B&C-1"},
    {"code": "4400", "name": "Jehlum", "bc": "B&C-1"},
    {"code": "4600", "name": "Rawalpindi", "bc": "B&C-1"},
    {"code": "4700", "name": "Islamabad East", "bc": "B&C-1"},
    {"code": "4800", "name": "Hasanabdal", "bc": "B&C-1"},
    {"code": "5100", "name": "Peshawar", "bc": "B&C-1"},
    {"code": "5200", "name": "Mardan", "bc": "B&C-1"},
    {"code": "5300", "name": "Abbottabad", "bc": "B&C-1"},
    {"code": "5400", "name": "Gilgit", "bc": "B&C-1"},
    {"code": "4900", "name": "Islamabad West", "bc": "B&C-1"},
]

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(64), nullable=True)
    role = db.Column(db.String(16), nullable=False)

    def get_id(self):
        return self.username

class Region(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    bc = db.Column(db.String(12), nullable=False)

# --- INITIAL DATA LOAD ---
@app.before_first_request
def setup():
    db.create_all()
    # Create mainadmin/chairman if not exist
    if not User.query.filter_by(username="mainadmin").first():
        pw = bcrypt.generate_password_hash("admin123").decode("utf-8")
        user = User(username="mainadmin", password=pw, name="Main Admin", role="admin")
        db.session.add(user)
    if not User.query.filter_by(username="chairman").first():
        pw = bcrypt.generate_password_hash("chairman123").decode("utf-8")
        user = User(username="chairman", password=pw, name="Chairman", role="chairman")
        db.session.add(user)
    # Load regions if not exists
    for reg in REGIONS_BC_MAP:
        if not Region.query.filter_by(code=reg["code"]).first():
            db.session.add(Region(code=reg["code"], name=reg["name"], bc=reg["bc"]))
    db.session.commit()

@login_manager.user_loader
def load_user(username):
    return User.query.filter_by(username=username).first()

# --- ROUTES ---

@app.route("/")
@login_required
def dashboard():
    user = current_user
    return render_template("dashboard.html", user=user)

@app.route("/regions")
@login_required
def regions():
    regions = Region.query.all()
    return render_template("regions.html", regions=regions)

@app.route("/add_region", methods=["GET", "POST"])
@login_required
def add_region():
    if request.method == "POST":
        code = request.form["code"]
        name = request.form["name"]
        bc = request.form["bc"]
        if not Region.query.filter_by(code=code).first():
            db.session.add(Region(code=code, name=name, bc=bc))
            db.session.commit()
            flash("Region added successfully.")
        else:
            flash("Region code already exists.")
        return redirect(url_for("regions"))
    return render_template("add_region.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
