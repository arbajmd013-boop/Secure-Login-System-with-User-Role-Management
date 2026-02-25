from pathlib import Path

import pytest

from app import create_app
from app.extensions import db
from app.models import User


@pytest.fixture()
def app(tmp_path: Path):
    database_path = tmp_path / "test.db"
    uploads_path = tmp_path / "uploads"
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "test-secret-key",
            "MAX_FAILED_ATTEMPTS": 3,
            "LOCKOUT_MINUTES": 1,
            "ACHIEVEMENTS_UPLOAD_FOLDER": str(uploads_path),
            "MAX_UPLOAD_FILE_SIZE": 2 * 1024 * 1024,
        }
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

        owner = User(
            username=app.config["OWNER_USERNAME"],
            email=app.config["OWNER_EMAIL"],
            role="owner",
            is_active=True,
        )
        owner.set_password(app.config["OWNER_PASSWORD"])

        admin = User(username="admin_user", email="admin@example.com", role="admin")
        admin.set_password("AdminPass123!")

        user = User(username="normal_user", email="user@example.com", role="user")
        user.set_password("UserPass123!!")

        db.session.add_all([owner, admin, user])
        db.session.commit()

    yield app


@pytest.fixture()
def client(app):
    return app.test_client()
