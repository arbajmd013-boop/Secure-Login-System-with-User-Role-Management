import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-in-production")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///secure_auth.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session security defaults
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"
    REMEMBER_COOKIE_HTTPONLY = True

    # App security controls
    MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
    LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(10 * 1024 * 1024)))

    MAX_UPLOAD_FILE_SIZE = int(os.getenv("MAX_UPLOAD_FILE_SIZE", str(5 * 1024 * 1024)))
    ALLOWED_UPLOAD_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "pdf"}
    ALLOWED_UPLOAD_MIME_TYPES = {
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/gif",
        "application/pdf",
    }
    ACHIEVEMENTS_UPLOAD_SUBDIR = "uploads/achievements"

    OWNER_EMAIL = os.getenv("OWNER_EMAIL", "owner123@gmail.com").strip().lower()
    OWNER_PASSWORD = os.getenv("OWNER_PASSWORD", "Ownerpassword1234@@##$$")
    OWNER_USERNAME = os.getenv("OWNER_USERNAME", "owner_private")

    DEFAULT_ABOUT_TEXT = os.getenv(
        "DEFAULT_ABOUT_TEXT",
        (
            "I am MD ARBAJ ANSARI, a cybersecurity practitioner focused on practical "
            "web application security. I have worked in bug bounty for about 1 year, "
            "with hands-on experience in authentication bugs, access-control issues, "
            "and secure coding validation."
        ),
    )
    DEFAULT_CONTACT_NAME = os.getenv("DEFAULT_CONTACT_NAME", "MD ARBAJ ANSARI")
    DEFAULT_CONTACT_EMAIL = os.getenv("DEFAULT_CONTACT_EMAIL", "arbajmd013@gmail.com").strip().lower()

    WTF_CSRF_TIME_LIMIT = None
