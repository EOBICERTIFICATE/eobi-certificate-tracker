from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin, bts, officer, ddg, chairman
    region_code = db.Column(db.String(10), nullable=True)
    beat_code = db.Column(db.String(10), nullable=True)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fir_number = db.Column(db.String(50), nullable=False)
    claimant_name = db.Column(db.String(150), nullable=False)
    claimant_cnic = db.Column(db.String(20), nullable=False)
    claimant_eobi = db.Column(db.String(30), nullable=False)
    employer_details = db.Column(db.Text, nullable=False)
    service_from = db.Column(db.Date, nullable=True)
    service_to = db.Column(db.Date, nullable=True)
    claim_region = db.Column(db.String(150), nullable=False)
    verification_region = db.Column(db.String(150), nullable=False)
    claim_region_code = db.Column(db.String(10), nullable=False)
    verification_region_code = db.Column(db.String(10), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='pending')
    uploaded_file = db.Column(db.String(255), nullable=True)
    drive_link = db.Column(db.String(255), nullable=True)
    remarks = db.Column(db.String(255), nullable=True)
    date_assigned = db.Column(db.DateTime, nullable=True)
    date_verified = db.Column(db.DateTime, nullable=True)
    delay_reason = db.Column(db.String(255), nullable=True)
