import os
import threading
from datetime import datetime
from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user
)
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

from models import db, User, Region, Certificate
from utils import (
    send_certificate_assignment_email, upload_to_drive,
    schedule_certificate_reminders, allowed_file, generate_tracking_id,
    assign_bts_email_settings, assign_officer_email_settings, random_password
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")
app.config.from_object('config.Config')

db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

_db_initialized = False
_db_lock = threading.Lock()

@app.before_request
def setup_db_once():
    global _db_initialized
    if not _db_initialized:
        with _db_lock:
            if not _db_initialized:
                db.create_all()
                # Add mainadmin/chairman if missing
                if not User.query.filter_by(username="mainadmin").first():
                    u = User(username="mainadmin", role="admin", password=bcrypt.generate_password_hash("admin123").decode('utf-8'), must_change_password=True)
                    db.session.add(u)
                if not User.query.filter_by(username="chairman").first():
                    u = User(username="chairman", role="chairman", password=bcrypt.generate_password_hash("chairman123").decode('utf-8'), must_change_password=True)
                    db.session.add(u)
                db.session.commit()
                _db_initialized = True

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

@app.route("/")
@login_required
def dashboard():
    # Add stats for summary dashboards
    stats = {
        "total": Certificate.query.count(),
        "pending": Certificate.query.filter_by(status="pending").count(),
        "completed": Certificate.query.filter_by(status="completed").count(),
        "overdue": Certificate.query.filter(Certificate.status=="pending", (datetime.utcnow() - Certificate.created_at).days > 14).count()
    }

    if current_user.role == "chairman":
        ddg_stats = User.get_ddg_stats()
        return render_template("dashboard_chairman.html", user=current_user, ddg_stats=ddg_stats, stats=stats)
    elif current_user.role == "admin":
        regions = Region.query.all()
        bts_list = User.query.filter_by(role="bts").all()
        return render_template("dashboard_admin.html", user=current_user, regions=regions, bts_list=bts_list, stats=stats)
    elif current_user.role == "ddg":
        rh_stats = User.get_rh_stats(current_user)
        return render_template("dashboard_ddg.html", user=current_user, rh_stats=rh_stats)
    elif current_user.role == "rh":
        bts_stats = User.get_bts_stats(current_user)
        return render_template("dashboard_rh.html", user=current_user, bts_stats=bts_stats)
    elif current_user.role == "drh":
        beat_stats = User.get_beat_stats(current_user)
        return render_template("dashboard_drh.html", user=current_user, beat_stats=beat_stats)
    elif current_user.role == "bts":
        certs = Certificate.query.filter_by(region_code=current_user.region_code).all()
        bts_email_settings = assign_bts_email_settings(current_user.region_code)
        return render_template("dashboard_bts.html", user=current_user, certs=certs, bts_email_settings=bts_email_settings)
    elif current_user.role == "officer":
        certs = Certificate.query.filter_by(assigned_officer=current_user.username).all()
        beat_email_settings = assign_officer_email_settings(current_user.username)
        return render_template("dashboard_beat.html", user=current_user, certs=certs, beat_email_settings=beat_email_settings)
    else:
        return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
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
    return redirect(url_for("login"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        pw1 = request.form["password1"]
        pw2 = request.form["password2"]
        if pw1 != pw2:
            flash("Passwords do not match.")
        elif len(pw1) < 6:
            flash("Password must be at least 6 characters.")
        else:
            current_user.password = bcrypt.generate_password_hash(pw1).decode('utf-8')
            current_user.must_change_password = False
            db.session.commit()
            flash("Password changed successfully!")
            return redirect(url_for('dashboard'))
    return render_template("change_password.html")

@app.route("/admin/add_bts", methods=["POST"])
@login_required
def add_bts():
    if current_user.role != "admin":
        flash("Access denied.")
        return redirect(url_for("dashboard"))
    username = request.form["username"]
    email = request.form["email"]
    region_code = request.form["region_code"]
    pw = random_password()
    if User.query.filter_by(username=username).first():
        flash("Username already exists!")
        return redirect(url_for("dashboard"))
    u = User(
        username=username, email=email, role="bts",
        region_code=region_code,
        password=bcrypt.generate_password_hash(pw).decode('utf-8'),
        must_change_password=True
    )
    db.session.add(u)
    db.session.commit()
    send_certificate_assignment_email(email, username, None, password=pw)
    flash("BTS added and login sent!")
    return redirect(url_for("dashboard"))

@app.route("/bts/settings", methods=["GET", "POST"])
@login_required
def bts_settings():
    if current_user.role != "bts":
        flash("Access denied.")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form["bts_email"]
        app_password = request.form["bts_app_password"]
        drive_folder = request.form["bts_drive_folder"]
        assign_bts_email_settings(current_user.region_code, email, app_password, drive_folder)
        flash("Settings updated!")
    return render_template("bts_settings.html", user=current_user)

@app.route("/bts/add_certificate", methods=["GET", "POST"])
@login_required
def add_certificate():
    if current_user.role != "bts":
        flash("Access denied.")
        return redirect(url_for("dashboard"))
    officer_list = User.get_officers_by_region(current_user.region_code)
    if request.method == "POST":
        fir = request.form["fir"]
        claimant_name = request.form["claimant_name"]
        cnic = request.form["cnic"]
        eobi_no = request.form["eobi_no"]
        employer = request.form["employer"]
        beat_code = request.form["beat_code"]
        assigned_officer = request.form["assigned_officer"]
        cross_verified = 'cross_verified' in request.form
        file = request.files["certificate_file"]
        if file and allowed_file(file.filename):
            filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            file.save(os.path.join("uploads", filename))
        else:
            filename = None
        officer = User.query.filter_by(username=assigned_officer).first()
        if not officer:
            officer_pw = random_password()
            officer = User(
                username=assigned_officer, role="officer", region_code=current_user.region_code,
                password=bcrypt.generate_password_hash(officer_pw).decode('utf-8'),
                must_change_password=True
            )
            db.session.add(officer)
            db.session.commit()
            send_certificate_assignment_email(officer.email, assigned_officer, None, password=officer_pw)
        tracking_id = generate_tracking_id(cnic, eobi_no, current_user.region_code, beat_code)
        cert = Certificate(
            tracking_id=tracking_id, fir=fir, claimant_name=claimant_name, cnic=cnic, eobi_no=eobi_no,
            employer=employer, beat_code=beat_code, region_code=current_user.region_code,
            assigned_officer=assigned_officer, file_name=filename, cross_verified=cross_verified
        )
        db.session.add(cert)
        db.session.commit()
        if filename:
            upload_to_drive(os.path.join("uploads", filename), filename, None, None)  # Add correct folder/id as needed
        send_certificate_assignment_email(officer.email, assigned_officer, cert)
        flash("Certificate added and assigned!")
        return redirect(url_for("dashboard"))
    return render_template("add_certificate.html", officer_list=officer_list, user=current_user)

@app.route("/officer/settings", methods=["GET", "POST"])
@login_required
def officer_settings():
    if current_user.role != "officer":
        flash("Access denied.")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form["bo_email"]
        app_password = request.form["bo_app_password"]
        drive_folder = request.form["bo_drive_folder"]
        assign_officer_email_settings(current_user.username, email, app_password, drive_folder)
        flash("Settings updated!")
    return render_template("officer_settings.html", user=current_user)

@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory("uploads", filename)

@app.route("/admin/run_reminders")
@login_required
def run_reminders():
    if current_user.role != "admin":
        flash("Access denied.")
        return redirect(url_for("dashboard"))
    schedule_certificate_reminders()
    flash("Reminders sent!")
    return redirect(url_for("dashboard"))

@app.route("/manage_officers", methods=["GET", "POST"])
@login_required
def manage_officers():
    if current_user.role != "admin":
        flash("Access denied!", "error")
        return redirect(url_for('dashboard'))
    regions = Region.query.order_by(Region.code).all()
    officers = User.query.filter_by(role='officer').order_by(User.region_code, User.username).all()
    if request.method == "POST":
        personal_no = request.form.get('personal_no')
        name = request.form.get('name')
        email = request.form.get('email')
        region_code = request.form.get('region_code')
        if not (personal_no and name and email and region_code):
            flash("All fields are required!", "error")
        elif User.query.filter_by(username=personal_no).first():
            flash("Officer with this Personal No already exists.", "error")
        else:
            password = random_password(8)
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            officer = User(
                username=personal_no,
                name=name,
                email=email,
                password=hashed_pw,
                role='officer',
                region_code=region_code,
                must_change_password=True
            )
            db.session.add(officer)
            db.session.commit()
            send_certificate_assignment_email(email, name, None, password=password)
            flash(f"Officer added. Username: {personal_no} (Password sent to email)", "success")
        return redirect(url_for("manage_officers"))
    return render_template(
        "manage_officers.html",
        regions=regions,
        officers=officers
    )

# ... Add more routes for manage_regions, reports, etc.

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
