import os
from dotenv import load_dotenv

load_dotenv()  # Loads environment variables from a .env file

class Config:
    # General
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super_secret_key_change_me'

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///eobi_certificates.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-Mail (Global default; per-region BTS credentials will be stored in DB/user input)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'your_default_global_email@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'your_global_app_password'
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or MAIL_USERNAME

    # File Uploads
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
    ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

    # Google Drive (Service account path, to be set per BTS/region)
    # For global default only; each BTS/region can provide their own
    GOOGLE_SERVICE_JSON = os.environ.get('GOOGLE_SERVICE_JSON') or 'service_account.json'
    GOOGLE_DRIVE_FOLDER_ID = os.environ.get('GOOGLE_DRIVE_FOLDER_ID') or 'your_drive_folder_id_here'

    # Reminder email settings
    REMINDER_DAYS = [15, 25, 45]  # days after assignment

    # Others
    # (Add any additional settings needed for your extensions)

# Optionally: add production/dev/test classes if you want to vary config by environment
