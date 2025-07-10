import os
from datetime import datetime
from app import app, db
from models import Certificate, User, Region
from utils import send_reminder_email, send_escalation_email

REMINDER_DAYS = [15, 25, 45]

def get_ddg_and_chairman_emails():
    # Get all DDG and Chairman emails from User table
    ddg_emails = [u.email for u in User.query.filter_by(role='ddg').all() if u.email]
    chairman_emails = [u.email for u in User.query.filter_by(role='chairman').all() if u.email]
    return ddg_emails, chairman_emails

def run_reminders():
    with app.app_context():
        now = datetime.utcnow()
        pending_certs = Certificate.query.filter_by(status='pending').all()

        ddg_emails, chairman_emails = get_ddg_and_chairman_emails()

        for cert in pending_certs:
            days_pending = (now - cert.created_at).days

            # Officer who certificate is assigned to
            assigned_officer = User.query.filter_by(username=cert.assigned_officer).first()
            # BTS region email (should be filled in Region table)
            region = Region.query.filter_by(code=cert.region_code).first()
            bts_email = getattr(region, 'bts_email', None) if region else None

            if days_pending in REMINDER_DAYS:
                # Send reminder to Beat Officer (assigned officer)
                if assigned_officer and assigned_officer.email:
                    send_reminder_email(
                        recipient=assigned_officer.email,
                        cert=cert,
                        days_pending=days_pending,
                        bts_email=bts_email
                    )
                    print(f"Sent reminder to {assigned_officer.email} for cert {cert.tracking_id} at {days_pending} days")
            elif days_pending > max(REMINDER_DAYS):
                # Escalate to DDG and Chairman after 45 days
                subject = f"[Escalation] Certificate {cert.tracking_id} pending over {days_pending} days"
                body = f"""
                Certificate {cert.tracking_id} for claimant {cert.claimant_name} (CNIC: {cert.cnic}) has been pending for {days_pending} days.
                Assigned Beat Officer: {assigned_officer.name if assigned_officer else cert.assigned_officer}
                Region: {region.name if region else cert.region_code}
                Status: {cert.status}

                Immediate action required.
                """
                for email in ddg_emails + chairman_emails:
                    send_escalation_email(email, subject, body)
                    print(f"Escalation sent to {email} for cert {cert.tracking_id}")

        print("All reminders and escalations processed.")

if __name__ == "__main__":
    run_reminders()
