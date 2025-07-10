from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=False, nullable=True)
    name = db.Column(db.String(64), nullable=True)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), nullable=False)
    region_code = db.Column(db.String(8), nullable=True)
    beat_code = db.Column(db.String(16), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    # For officer: personal no is stored in username
    def get_id(self):
        return str(self.id)

    @staticmethod
    def generate_temp_password(length=8):
        import random, string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def get_ddg_stats():
        # Returns list of DDGs and their region pendency
        from .models import Certificate
        data = []
        ddgs = User.query.filter_by(role="ddg").all()
        for d in ddgs:
            certs = Certificate.query.filter_by(region_code=d.region_code).all()
            pending = len([c for c in certs if c.status == "pending"])
            overdue = len([c for c in certs if c.status == "pending" and (datetime.utcnow() - c.created_at).days > 14])
            data.append({"ddg": d, "pending": pending, "overdue": overdue})
        return data

    @staticmethod
    def get_rh_stats(ddg_user):
        # Returns list of RHs under a DDG and their stats
        data = []
        rhs = User.query.filter_by(role="rh", region_code=ddg_user.region_code).all()
        for r in rhs:
            pending = Certificate.query.filter_by(region_code=r.region_code, status="pending").count()
            completed = Certificate.query.filter_by(region_code=r.region_code, status="completed").count()
            data.append({"rh": r, "pending": pending, "completed": completed})
        return data

    @staticmethod
    def get_bts_stats(rh_user):
        data = []
        bts_list = User.query.filter_by(role="bts", region_code=rh_user.region_code).all()
        for b in bts_list:
            pending = Certificate.query.filter_by(region_code=b.region_code, status="pending").count()
            completed = Certificate.query.filter_by(region_code=b.region_code, status="completed").count()
            data.append({"bts": b, "pending": pending, "completed": completed})
        return data

    @staticmethod
    def get_beat_stats(drh_user):
        data = []
        officers = User.query.filter_by(role="officer", region_code=drh_user.region_code).all()
        for o in officers:
            pending = Certificate.query.filter_by(assigned_officer=o.username, status="pending").count()
            completed = Certificate.query.filter_by(assigned_officer=o.username, status="completed").count()
            data.append({"officer": o, "pending": pending, "completed": completed})
        return data

    @staticmethod
    def get_officers_by_region(region_code):
        officers = User.query.filter_by(role="officer", region_code=region_code).all()
        return [o.username for o in officers]

class Region(db.Model):
    __tablename__ = 'region'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    bc = db.Column(db.String(8), nullable=True)
    bts_email = db.Column(db.String(128), nullable=True)      # For BTS incharge email integration
    bts_app_password = db.Column(db.String(64), nullable=True)
    bts_drive_folder = db.Column(db.String(128), nullable=True)

class Certificate(db.Model):
    __tablename__ = 'certificate'
    id = db.Column(db.Integer, primary_key=True)
    tracking_id = db.Column(db.String(32), unique=True, nullable=False)
    fir = db.Column(db.String(32), nullable=True)
    claimant_name = db.Column(db.String(64), nullable=False)
    cnic = db.Column(db.String(15), nullable=False)
    eobi_no = db.Column(db.String(15), nullable=False)
    employer = db.Column(db.String(128), nullable=False)
    beat_code = db.Column(db.String(16), nullable=True)
    region_code = db.Column(db.String(8), nullable=False)
    assigned_officer = db.Column(db.String(32), nullable=True)
    file_name = db.Column(db.String(128), nullable=True)
    status = db.Column(db.String(32), default="pending")
    days_pending = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    cross_verified = db.Column(db.Boolean, default=False)
    history = db.Column(db.Text, nullable=True)  # Store assignment history (as JSON, comma list, or text)

    def get_pending_days(self):
        return (datetime.utcnow() - self.created_at).days

    def add_history(self, action, by_user):
        import json
        hist = []
        if self.history:
            try:
                hist = json.loads(self.history)
            except Exception:
                hist = []
        hist.append({
            "action": action,
            "by": by_user,
            "timestamp": datetime.utcnow().isoformat()
        })
        self.history = json.dumps(hist)

    @staticmethod
    def get_region_certificates(region_code):
        return Certificate.query.filter_by(region_code=region_code).all()
