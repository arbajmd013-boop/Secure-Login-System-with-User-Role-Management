from pathlib import Path

from flask import Flask
from sqlalchemy import inspect, text

from app.config import Config
from app.extensions import csrf, db, login_manager


def _generate_unique_owner_username(base_username: str) -> str:
    from app.models import User

    candidate = base_username
    suffix = 1
    while db.session.query(User.id).filter_by(username=candidate).first() is not None:
        candidate = f"{base_username}_{suffix}"
        suffix += 1
    return candidate


def ensure_owner_account(app: Flask) -> None:
    from app.models import User

    owner_email = app.config["OWNER_EMAIL"]
    owner_password = app.config["OWNER_PASSWORD"]
    preferred_username = app.config["OWNER_USERNAME"]

    owner = db.session.query(User).filter_by(email=owner_email).first()
    if owner is None:
        username = _generate_unique_owner_username(preferred_username)
        owner = User(username=username, email=owner_email, role="owner", is_active=True)
        owner.set_password(owner_password)
        db.session.add(owner)
        db.session.commit()
        return

    updated = False
    if owner.role != "owner":
        owner.role = "owner"
        updated = True
    if not owner.is_active:
        owner.is_active = True
        updated = True
    if not owner.check_password(owner_password):
        owner.set_password(owner_password)
        updated = True

    if updated:
        db.session.commit()


def upsert_site_content(key: str, value: str) -> None:
    from app.models import SiteContent

    content = db.session.query(SiteContent).filter_by(key=key).first()
    if content is None:
        content = SiteContent(key=key, value=value)
        db.session.add(content)
    elif not content.value:
        content.value = value


def ensure_default_site_content(app: Flask) -> None:
    upsert_site_content("about_text", app.config["DEFAULT_ABOUT_TEXT"])
    upsert_site_content("contact_name", app.config["DEFAULT_CONTACT_NAME"])
    upsert_site_content("contact_email", app.config["DEFAULT_CONTACT_EMAIL"])
    db.session.commit()


def run_schema_upgrades() -> None:
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    if "users" in tables:
        columns = {column["name"] for column in inspector.get_columns("users")}
        if "is_active" not in columns:
            with db.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1")
                )

    if "achievements" in tables:
        achievement_columns = {column["name"] for column in inspector.get_columns("achievements")}
        if "event_date" not in achievement_columns:
            with db.engine.begin() as connection:
                connection.execute(text("ALTER TABLE achievements ADD COLUMN event_date DATE"))


def ensure_favicon_file(app: Flask) -> None:
    static_folder = Path(app.static_folder)
    static_folder.mkdir(parents=True, exist_ok=True)
    static_favicon = static_folder / "favicon.ico"
    bundled_favicon = Path(__file__).resolve().parent / "assets" / "favicon.ico"

    if static_favicon.is_file():
        return

    if bundled_favicon.is_file():
        static_favicon.write_bytes(bundled_favicon.read_bytes())


def create_app(test_config: dict | None = None) -> Flask:
    project_root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
    )
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from app.routes import main

    app.register_blueprint(main)
    ensure_favicon_file(app)

    configured_upload_dir = app.config.get("ACHIEVEMENTS_UPLOAD_FOLDER")
    if configured_upload_dir:
        upload_dir = Path(configured_upload_dir)
    else:
        upload_dir = Path(app.instance_path) / app.config["ACHIEVEMENTS_UPLOAD_SUBDIR"]
    upload_dir.mkdir(parents=True, exist_ok=True)
    app.config["ACHIEVEMENTS_UPLOAD_FOLDER"] = str(upload_dir)

    with app.app_context():
        db.create_all()
        run_schema_upgrades()
        ensure_owner_account(app)
        ensure_default_site_content(app)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    return app
