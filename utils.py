import os
import smtplib
import threading
import json
import random
import string
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import current_app
from werkzeug.utils import secure_filename

from models import db, User, Certificate, Region

# === ALLOWED FILE UTILS ===

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    """
    Check if a file is an allowed type.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# === EMAIL UTILS ===

def send_email_smtp(subject, recipients, body, mail_user, mail_pass):
    """
    Send email via SMTP with provided credentials.
    Handles single and multiple recipients.
    """
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        msg = MIMEMultipart()
        msg['From'] = mail_user
        msg['To'] = ", ".join(recipients) if isinstance(recipients, list) else recipients
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(mail_user, mail_pass)
        server.sendmail(mail_user, recipients, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

def send_certificate_assignment_email(officer_email, officer_name, certificate, password=None, sender_email=None, sender_pass=None):
    """
    Send a certificate assignment (or re-assignment) email to a beat officer.
    Optionally includes login credentials for new officers.
    """
    subject = f"New Certificate Assigned (Tracking ID: {certificate.tracking_id})"
    body = f"""Dear {officer_name},

You have been assigned a certificate for verification.

Tracking ID: {certificate.tracking_id}
Claimant Name: {certificate.claimant_name}
CNIC: {certificate.cnic}
FIR: {certificate.fir}
EOBI #: {certificate.eobi_no}
Employer: {certificate.employer}
"""
    if password:
        body += f"\nYour portal login: {officer_email}\nTemporary Password: {password}\n"

    body += "\nPlease login to the EOBI Certificate Tracker to view details and respond."

    # Use specific BTS sender if set, else fallback to env
    mail_user = sender_email or os.environ.get("MAIL_USERNAME")
    mail_pass = sender_pass or os.environ.get("MAIL_PASSWORD")
    return send_email_smtp(subject, officer_email, body, mail_user, mail_pass)

def send_certificate_email(recipient, subject, body, sender_email=None, sender_pass=None):
    """
    Generic email send function for simple notification (for admin use).
    """
    mail_user = sender_email or os.environ.get("MAIL_USERNAME")
    mail_pass = sender_pass or os.environ.get("MAIL_PASSWORD")
    return send_email_smtp(subject, recipient, body, mail_user, mail_pass)

def send_reminder_email(officer_email, certificate, reminder_level=1, cc_emails=None, sender_email=None, sender_pass=None):
    """
    Send a reminder email to a beat officer. Escalates at 3rd reminder.
    """
    levels = {
        1: "[REMINDER] Certificate Pending 15 Days",
        2: "[REMINDER] Certificate Pending 25 Days",
        3: "[FINAL REMINDER] Certificate Pending 45+ Days - Escalated"
    }
    subject = levels.get(reminder_level, "[REMINDER] Certificate Pending")
    body = f"""This is a reminder regarding your pending certificate:

Tracking ID: {certificate.tracking_id}
Claimant Name: {certificate.claimant_name}
Days Pending: {certificate.get_pending_days() if hasattr(certificate, 'get_pending_days') else (datetime.utcnow()-certificate.created_at).days}

Please complete the verification and upload required documents as soon as possible.
"""
    # Add escalation recipients for 3rd reminder
    recipients = [officer_email]
    if reminder_level == 3 and cc_emails:
        recipients += cc_emails

    mail_user = sender_email or os.environ.get("MAIL_USERNAME")
    mail_pass = sender_pass or os.environ.get("MAIL_PASSWORD")
    return send_email_smtp(subject, recipients, body, mail_user, mail_pass)

# === GOOGLE DRIVE UTILS ===

def upload_to_drive(local_path, filename, drive_folder_id, service_json_path):
    """
    Upload a file to Google Drive using a service account JSON.
    Returns the Google Drive file ID or None on failure.
    """
    try:
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaFileUpload
        from google.oauth2 import service_account

        SCOPES = ['https://www.googleapis.com/auth/drive.file']
        creds = service_account.Credentials.from_service_account_file(
            service_json_path, scopes=SCOPES
        )
        drive_service = build('drive', 'v3', credentials=creds)
        file_metadata = {
            'name': filename,
            'parents': [drive_folder_id]
        }
        media = MediaFileUpload(local_path, resumable=True)
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        return file.get('id')
    except Exception as e:
        print(f"[DRIVE UPLOAD ERROR] {e}")
        return None

# === TRACKING ID ===

def generate_tracking_id(cnic, eobi_no, region, beat):
    rand = ''.join(random.choices(string.digits, k=3))
    return f"{region}-{beat}-{cnic[-4:]}-{eobi_no[-4:]}-{rand}"

def create_tracking_id(cnic, eobi_no, region, beat):
    return generate_tracking_id(cnic, eobi_no, region, beat)

# === PASSWORD ===

def random_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# === REMINDER SCHEDULER ===

def schedule_reminders():
    """
    Check all pending certificates and send reminders as needed.
    """
    all_certs = Certificate.query.filter_by(status="pending").all()
    for cert in all_certs:
        days = (datetime.utcnow() - cert.created_at).days
        if days == 15:
            send_reminder_email(cert.assigned_officer, cert, 1)
        elif days == 25:
            send_reminder_email(cert.assigned_officer, cert, 2)
        elif days >= 45:
            # get CC list of DDG/Chairman etc as needed
            send_reminder_email(cert.assigned_officer, cert, 3, cc_emails=['ddg@example.com', 'chairman@example.com'])

def schedule_certificate_reminders(certificate_id, officer_email, sender_email=None, sender_pass=None):
    """
    Schedule reminders for certificate verification at 15, 25, 45 days.
    (Note: This example is not persistent—use a job queue in production.)
    """
    def reminder_job(reminder_level):
        certificate = Certificate.query.get(certificate_id)
        if not certificate or certificate.status == "completed":
            return
        send_reminder_email(
            officer_email,
            certificate,
            reminder_level=reminder_level,
            sender_email=sender_email,
            sender_pass=sender_pass
        )
    threading.Timer(15*24*60*60, lambda: reminder_job(1)).start()
    threading.Timer(25*24*60*60, lambda: reminder_job(2)).start()
    threading.Timer(45*24*60*60, lambda: reminder_job(3)).start()

# === COLOR CODING (for dashboard tables) ===

def get_row_color(days_pending):
    if days_pending >= 45:
        return "red"
    elif days_pending >= 25:
        return "black"
    elif days_pending >= 15:
        return "yellow"
    else:
        return "green"

# === BTS/BEAT OFFICER EMAIL/DRIVE SETTINGS (stub functions for extensibility) ===

def assign_bts_email_settings(region_code, email=None, app_password=None, drive_folder=None):
    """
    Save/assign BTS region's email/app password/drive folder as required.
    You may store in a dedicated table, or .env, or as a JSON in the Region model.
    """
    # Stub: update your data model as required
    reg = Region.query.filter_by(code=region_code).first()
    if reg:
        # For real app: save fields to reg.bts_email, reg.bts_drive_folder, etc
        db.session.commit()

def assign_officer_email_settings(username, email=None, app_password=None, drive_folder=None):
    """
    Save/assign beat officer email/app password/drive folder as required.
    """
    # Stub: update your data model as required
    user = User.query.filter_by(username=username).first()
    if user:
        # For real app: save fields to user.officer_email, user.officer_drive_folder, etc
        db.session.commit()

# === OFFICER MANAGEMENT ===

def create_officer(username, email, name, password=None, region_code=None, beat_code=None):
    from app import bcrypt  # To avoid circular import
    user = User.query.filter_by(username=username).first()
    if user:
        return user, False
    if password is None:
        password = random_password(8)
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    officer = User(
        username=username,
        email=email,
        name=name,
        password=hashed_pw,
        role='officer',
        region_code=region_code,
        beat_code=beat_code,
        must_change_password=True
    )
    db.session.add(officer)
    db.session.commit()
    return officer, True

# === HISTORY HELPERS ===

def add_certificate_history(certificate, action, user):
    """
    Add an action to the certificate's history log.
    """
    hist = []
    if certificate.history:
        try:
            hist = json.loads(certificate.history)
        except Exception:
            hist = []
    hist.append({
        "action": action,
        "by": user,
        "timestamp": datetime.utcnow().isoformat()
    })
    certificate.history = json.dumps(hist)
    db.session.commit()

# === __all__ for import hygiene ===

__all__ = [
    "allowed_file",
    "send_certificate_assignment_email",
    "send_certificate_email",
    "send_reminder_email",
    "upload_to_drive",
    "generate_tracking_id",
    "create_tracking_id",
    "random_password",
    "schedule_reminders",
    "schedule_certificate_reminders",
    "get_row_color",
    "assign_bts_email_settings",
    "assign_officer_email_settings",
    "create_officer",
    "add_certificate_history",
]

