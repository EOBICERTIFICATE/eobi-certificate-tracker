import os
import smtplib
import threading
import json
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import current_app
from werkzeug.utils import secure_filename

from models import db, User, Certificate, Region

# === EMAIL UTILS ===

def send_email_smtp(subject, recipients, body, mail_user, mail_pass):
    """Send email via SMTP with given credentials."""
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

def send_certificate_assignment_email(officer_email, officer_name, certificate, password=None):
    """Send assignment email (new or re-assigned) to officer."""
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
        body += f"Your portal login: {officer_email}\nTemporary Password: {password}\n\n"

    body += "Please login to the EOBI Certificate Tracker to view details and respond.\n"
    return send_email_smtp(
        subject,
        officer_email,
        body,
        os.environ.get("MAIL_USERNAME"),
        os.environ.get("MAIL_PASSWORD")
    )

def send_reminder_email(officer_email, certificate, reminder_level=1):
    """Send reminder to officer, escalate at 3rd."""
    levels = {
        1: "[REMINDER] Certificate Pending 15 Days",
        2: "[REMINDER] Certificate Pending 25 Days",
        3: "[FINAL REMINDER] Certificate Pending 45+ Days - Escalated"
    }
    subject = levels.get(reminder_level, "[REMINDER] Certificate Pending")
    body = f"""This is a reminder regarding your pending certificate:

Tracking ID: {certificate.tracking_id}
Claimant Name: {certificate.claimant_name}
Days Pending: {certificate.get_pending_days()}

Please complete the verification and upload required documents as soon as possible.
"""
    # Optionally escalate (CC to DDG/Chairman)
    # (In actual app: query DDG, Chairman emails as required)
    return send_email_smtp(
        subject,
        officer_email,
        body,
        os.environ.get("MAIL_USERNAME"),
        os.environ.get("MAIL_PASSWORD")
    )

# === GOOGLE DRIVE UTILS ===

def upload_to_drive(local_path, filename, drive_folder_id, service_json_path):
    """
    Uploads a file to Google Drive folder using service account JSON.
    Args:
        local_path: Path to the file on server
        filename: Filename to save as
        drive_folder_id: Google Drive folder ID to upload into
        service_json_path: Path to your service account credentials .json
    Returns:
        Google Drive file id or None
    """
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    from google.oauth2 import service_account

    try:
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
    import random, string
    rand = ''.join(random.choices(string.digits, k=3))
    return f"{region}-{beat}-{cnic[-4:]}-{eobi_no[-4:]}-{rand}"

# === PASSWORD ===

def random_password(length=8):
    import random, string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# === REMINDER SCHEDULER ===

def schedule_certificate_reminders(certificate_id, officer_email):
    """
    Schedule reminders at 15, 25, 45 days after certificate creation.
    """
    # This is just a basic illustration.
    # In production, use a job scheduler like Celery/Redis.
    def reminder_job(reminder_level):
        certificate = Certificate.query.get(certificate_id)
        if not certificate or certificate.status == "completed":
            return
        send_reminder_email(officer_email, certificate, reminder_level)
    # 15, 25, 45 days
    threading.Timer(15*24*60*60, lambda: reminder_job(1)).start()
    threading.Timer(25*24*60*60, lambda: reminder_job(2)).start()
    threading.Timer(45*24*60*60, lambda: reminder_job(3)).start()

# === COLOR CODING ===

def get_row_color(days_pending):
    if days_pending >= 45:
        return "red"
    elif days_pending >= 25:
        return "black"
    elif days_pending >= 15:
        return "yellow"
    else:
        return "green"

# === OFFICER MANAGEMENT ===

def create_officer(username, email, name, password=None, region_code=None, beat_code=None):
    """Create a new beat officer if not exists, returns User object."""
    from app import bcrypt  # Import here to avoid circular import
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
    # Optionally: send email with credentials here
    return officer, True

# === HISTORY HELPERS ===

def add_certificate_history(certificate, action, user):
    import json
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

# === ANY MORE HELPERS YOU NEED HERE... ===
