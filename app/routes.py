from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import Achievement, SiteContent, User
from app.security import (
    generate_captcha,
    is_strong_password,
    is_valid_email,
    is_valid_username,
    roles_required,
)

main = Blueprint("main", __name__)


@main.app_errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="Access denied."), 403


@main.app_errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="Page not found."), 404


@main.app_errorhandler(500)
def internal_error(_error):
    db.session.rollback()
    return render_template("error.html", code=500, message="Server error."), 500


@main.route("/favicon.ico")
def favicon():
    static_favicon = Path(current_app.static_folder) / "favicon.ico"
    if static_favicon.is_file():
        return send_from_directory(
            current_app.static_folder,
            "favicon.ico",
            mimetype="image/vnd.microsoft.icon",
            max_age=86400,
        )

    bundled_favicon = Path(__file__).resolve().parent / "assets" / "favicon.ico"
    if bundled_favicon.is_file():
        return send_file(
            bundled_favicon,
            mimetype="image/vnd.microsoft.icon",
            max_age=86400,
        )

    abort(404)


def set_login_captcha() -> str:
    question, answer = generate_captcha()
    session["captcha_question"] = question
    session["captcha_answer"] = answer
    return question


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def is_owner() -> bool:
    return bool(current_user.is_authenticated and current_user.role == "owner")


def get_site_content_value(key: str, fallback: str) -> str:
    content = db.session.query(SiteContent).filter_by(key=key).first()
    if content and content.value:
        return content.value
    return fallback


def set_site_content_value(key: str, value: str) -> None:
    content = db.session.query(SiteContent).filter_by(key=key).first()
    if content is None:
        content = SiteContent(key=key, value=value)
        db.session.add(content)
    else:
        content.value = value


def validate_registration_input(username: str, email: str, password: str, role: str) -> list[str]:
    allowed_roles = {"admin", "user"}
    errors = []
    if not username or not email or not password or not role:
        errors.append("All fields are required.")

    if username and not is_valid_username(username):
        errors.append("Username must be 3-30 chars and only letters, numbers, underscores.")

    if email and not is_valid_email(email):
        errors.append("Invalid email format.")

    if password and not is_strong_password(password):
        errors.append(
            "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol."
        )

    if role not in allowed_roles:
        errors.append("Invalid role selected.")

    return errors


def create_user_account(username: str, email: str, password: str, role: str) -> tuple[User | None, list[str]]:
    errors = validate_registration_input(username, email, password, role)
    if errors:
        return None, errors

    user = User(username=username, email=email, role=role)
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return None, ["Username or email already exists."]

    return user, []


def get_sorted_achievements() -> tuple[list[Achievement], list[Achievement]]:
    all_achievements = Achievement.query.order_by(desc(Achievement.created_at), desc(Achievement.id)).all()
    sorted_items = sorted(
        all_achievements,
        key=lambda item: (
            item.event_date or item.created_at.date(),
            item.created_at,
            item.id,
        ),
        reverse=True,
    )
    hall_of_fame = [item for item in sorted_items if item.category == "hall_of_fame"]
    bounty_posts = [item for item in sorted_items if item.category == "bounty_post"]
    return hall_of_fame, bounty_posts


def is_allowed_upload(filename: str, mime_type: str) -> bool:
    extension = Path(filename).suffix.lower().lstrip(".")
    allowed_extensions = current_app.config["ALLOWED_UPLOAD_EXTENSIONS"]
    allowed_mime_types = current_app.config["ALLOWED_UPLOAD_MIME_TYPES"]
    return extension in allowed_extensions and mime_type in allowed_mime_types


def has_valid_signature(file_storage, extension: str) -> bool:
    stream = file_storage.stream
    current_position = stream.tell()
    header = stream.read(16)
    stream.seek(current_position)

    if extension == "png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {"jpg", "jpeg"}:
        return header.startswith(b"\xff\xd8\xff")
    if extension == "gif":
        return header.startswith((b"GIF87a", b"GIF89a"))
    if extension == "webp":
        return len(header) >= 12 and header.startswith(b"RIFF") and header[8:12] == b"WEBP"
    if extension == "pdf":
        return header.startswith(b"%PDF")

    return False


def get_file_size(file_storage) -> int:
    stream = file_storage.stream
    current_position = stream.tell()
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(current_position)
    return size


def parse_achievement_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_block_minutes(value: str) -> int | None:
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return None

    if minutes < 1 or minutes > 1440:
        return None

    return minutes


def parse_scroll_position(value: str) -> int | None:
    try:
        scroll_position = int(value)
    except (TypeError, ValueError):
        return None

    if scroll_position < 0 or scroll_position > 2_000_000:
        return None

    return scroll_position


def redirect_to_admin_dashboard(
    focus_user_id: int | None = None, scroll_position: int | None = None
):
    params: dict[str, int] = {}
    if focus_user_id is not None:
        params["focus"] = focus_user_id
    if scroll_position is not None:
        params["scroll"] = scroll_position
    return redirect(url_for("main.admin_dashboard", **params))


def get_admin_manageable_user(user_id: int) -> User:
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.role == "owner":
        abort(403)
    return user


@main.route("/")
def home():
    about_text = get_site_content_value("about_text", current_app.config["DEFAULT_ABOUT_TEXT"])
    return render_template("home.html", about_text=about_text, can_manage_owner=is_owner())


@main.route("/achievements")
@main.route("/achevement")
def achievements_page():
    hall_of_fame, bounty_posts = get_sorted_achievements()
    return render_template(
        "achievements.html",
        hall_of_fame=hall_of_fame,
        bounty_posts=bounty_posts,
        can_manage_owner=is_owner(),
    )


@main.route("/contact")
def contact_page():
    contact_name = get_site_content_value("contact_name", current_app.config["DEFAULT_CONTACT_NAME"])
    contact_email = get_site_content_value("contact_email", current_app.config["DEFAULT_CONTACT_EMAIL"])
    return render_template(
        "contact.html",
        contact_name=contact_name,
        contact_email=contact_email,
        can_manage_owner=is_owner(),
    )


@main.route("/owner/content/about", methods=["POST"])
@login_required
@roles_required("owner")
def update_about_content():
    about_text = request.form.get("about_text", "").strip()

    if len(about_text) < 40 or len(about_text) > 5000:
        flash("About text must be between 40 and 5000 characters.", "danger")
        return redirect(url_for("main.home"))

    set_site_content_value("about_text", about_text)
    db.session.commit()
    flash("About content updated.", "success")
    return redirect(url_for("main.home"))


@main.route("/owner/content/contact", methods=["POST"])
@login_required
@roles_required("owner")
def update_contact_content():
    contact_name = request.form.get("contact_name", "").strip()
    contact_email = request.form.get("contact_email", "").strip().lower()

    errors = []
    if len(contact_name) < 2 or len(contact_name) > 120:
        errors.append("Contact name must be between 2 and 120 characters.")

    if not is_valid_email(contact_email):
        errors.append("Invalid contact email format.")

    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("main.contact_page"))

    set_site_content_value("contact_name", contact_name)
    set_site_content_value("contact_email", contact_email)
    db.session.commit()

    flash("Contact details updated.", "success")
    return redirect(url_for("main.contact_page"))


@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = "user"

        if password != confirm_password:
            flash("Password and Re-enter Password must match.", "danger")
            return render_template("register.html")

        _user, errors = create_user_account(username, email, password, role)
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("register.html")

        flash("Registration successful. You can log in now.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html")


@main.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == "owner":
            return redirect(url_for("main.achievements_page"))
        if current_user.role == "admin":
            return redirect(url_for("main.admin_add_member_page"))
        return redirect(url_for("main.user_dashboard"))

    captcha_question = session.get("captcha_question") or set_login_captcha()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        captcha_answer = request.form.get("captcha_answer", "").strip()

        if captcha_answer != session.get("captcha_answer"):
            flash("Invalid CAPTCHA. Try again.", "danger")
            return render_template("login.html", captcha_question=set_login_captcha())

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Invalid credentials.", "danger")
            return render_template("login.html", captcha_question=set_login_captcha())

        if not user.is_active:
            flash("Account disabled by admin. Contact administrator.", "danger")
            return render_template("login.html", captcha_question=set_login_captcha())

        if user.is_locked():
            minutes = int(max((user.lockout_until - utcnow_naive()).total_seconds() // 60, 1))
            flash(f"Account locked. Try again in {minutes} minute(s).", "warning")
            return render_template("login.html", captcha_question=set_login_captcha())

        if user.check_password(password):
            user.failed_login_attempts = 0
            user.lockout_until = None
            db.session.commit()

            login_user(user)
            session.permanent = True
            flash("Login successful.", "success")

            if user.role == "owner":
                return redirect(url_for("main.achievements_page"))
            if user.role == "admin":
                return redirect(url_for("main.admin_add_member_page"))
            return redirect(url_for("main.user_dashboard"))

        user.failed_login_attempts += 1
        max_attempts = current_app.config["MAX_FAILED_ATTEMPTS"]
        if user.failed_login_attempts >= max_attempts:
            lockout_minutes = current_app.config["LOCKOUT_MINUTES"]
            user.lockout_until = utcnow_naive() + timedelta(minutes=lockout_minutes)
            user.failed_login_attempts = 0
            db.session.commit()
            flash(
                f"Account locked due to too many failed attempts. Wait {lockout_minutes} minutes.",
                "danger",
            )
            return render_template("login.html", captcha_question=set_login_captcha())

        db.session.commit()
        remaining_attempts = max_attempts - user.failed_login_attempts
        flash(
            f"Invalid credentials. {remaining_attempts} attempt(s) left before lockout.",
            "danger",
        )
        return render_template("login.html", captcha_question=set_login_captcha())

    return render_template("login.html", captcha_question=captcha_question)


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.pop("captcha_question", None)
    session.pop("captcha_answer", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("main.login"))


@main.route("/dashboard")
@login_required
@roles_required("user")
def user_dashboard():
    return render_template("user_dashboard.html")


@main.route("/members")
@login_required
@roles_required("admin", "user")
def members():
    admins = User.query.filter_by(role="admin").order_by(User.username.asc()).all()
    users = User.query.filter_by(role="user").order_by(User.username.asc()).all()
    return render_template("members.html", admins=admins, users=users)


@main.route("/achievements/upload", methods=["POST"])
@login_required
@roles_required("owner")
def upload_achievement():
    category = request.form.get("category", "").strip().lower()
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    achieved_on_raw = request.form.get("achieved_on", "").strip()
    proof_file = request.files.get("proof_file")

    event_date = parse_achievement_date(achieved_on_raw)

    errors = []
    if category not in {"hall_of_fame", "bounty_post"}:
        errors.append("Invalid achievement category.")

    if len(title) < 3 or len(title) > 140:
        errors.append("Title must be between 3 and 140 characters.")

    if len(description) > 1200:
        errors.append("Description should be 1200 characters or fewer.")

    if achieved_on_raw and event_date is None:
        errors.append("Invalid achievement date.")

    if not proof_file or proof_file.filename == "":
        errors.append("Upload file is required.")

    sanitized_filename = secure_filename(proof_file.filename if proof_file else "")
    mime_type = (proof_file.mimetype if proof_file else "").lower()

    if not sanitized_filename:
        errors.append("Invalid file name.")
    elif not is_allowed_upload(sanitized_filename, mime_type):
        errors.append("Only PNG/JPG/JPEG/WEBP/GIF/PDF files are allowed.")
    else:
        extension = Path(sanitized_filename).suffix.lower().lstrip(".")
        if not has_valid_signature(proof_file, extension):
            errors.append("File content does not match the selected file type.")

    if proof_file and not errors:
        file_size = get_file_size(proof_file)
        max_file_size = current_app.config["MAX_UPLOAD_FILE_SIZE"]
        if file_size <= 0 or file_size > max_file_size:
            errors.append(f"File size must be between 1 byte and {max_file_size // (1024 * 1024)} MB.")
        else:
            extension = Path(sanitized_filename).suffix.lower()
            generated_filename = f"{uuid4().hex}{extension}"
            upload_dir = Path(current_app.config["ACHIEVEMENTS_UPLOAD_FOLDER"])
            destination = upload_dir / generated_filename

    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("main.achievements_page"))

    proof_file.save(destination)

    achievement = Achievement(
        category=category,
        title=title,
        description=description,
        event_date=event_date,
        original_filename=sanitized_filename,
        stored_filename=generated_filename,
        mime_type=mime_type,
        file_size=file_size,
        uploader_id=current_user.id,
    )
    db.session.add(achievement)
    db.session.commit()

    flash("Achievement uploaded successfully.", "success")
    return redirect(url_for("main.achievements_page"))


@main.route("/achievements/<int:achievement_id>/edit", methods=["POST"])
@login_required
@roles_required("owner")
def edit_achievement(achievement_id: int):
    achievement = db.session.get(Achievement, achievement_id)
    if not achievement:
        abort(404)

    category = request.form.get("category", "").strip().lower()
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    achieved_on_raw = request.form.get("achieved_on", "").strip()
    proof_file = request.files.get("proof_file")

    event_date = parse_achievement_date(achieved_on_raw)

    errors = []
    if category not in {"hall_of_fame", "bounty_post"}:
        errors.append("Invalid achievement category.")

    if len(title) < 3 or len(title) > 140:
        errors.append("Title must be between 3 and 140 characters.")

    if len(description) > 1200:
        errors.append("Description should be 1200 characters or fewer.")

    if achieved_on_raw and event_date is None:
        errors.append("Invalid achievement date.")

    has_new_file = bool(proof_file and proof_file.filename and proof_file.filename.strip())
    generated_filename = ""
    sanitized_filename = ""
    mime_type = ""
    destination = None
    file_size = 0

    if has_new_file:
        sanitized_filename = secure_filename(proof_file.filename)
        mime_type = (proof_file.mimetype or "").lower()
        if not sanitized_filename:
            errors.append("Invalid file name.")
        elif not is_allowed_upload(sanitized_filename, mime_type):
            errors.append("Only PNG/JPG/JPEG/WEBP/GIF/PDF files are allowed.")
        else:
            extension = Path(sanitized_filename).suffix.lower().lstrip(".")
            if not has_valid_signature(proof_file, extension):
                errors.append("File content does not match the selected file type.")

        if not errors:
            file_size = get_file_size(proof_file)
            max_file_size = current_app.config["MAX_UPLOAD_FILE_SIZE"]
            if file_size <= 0 or file_size > max_file_size:
                errors.append(
                    f"File size must be between 1 byte and {max_file_size // (1024 * 1024)} MB."
                )
            else:
                extension = Path(sanitized_filename).suffix.lower()
                generated_filename = f"{uuid4().hex}{extension}"
                upload_dir = Path(current_app.config["ACHIEVEMENTS_UPLOAD_FOLDER"])
                destination = upload_dir / generated_filename

    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("main.achievements_page"))

    old_stored_filename = achievement.stored_filename
    achievement.category = category
    achievement.title = title
    achievement.description = description
    achievement.event_date = event_date

    if has_new_file and destination is not None:
        proof_file.save(destination)
        achievement.original_filename = sanitized_filename
        achievement.stored_filename = generated_filename
        achievement.mime_type = mime_type
        achievement.file_size = file_size

    db.session.commit()

    if has_new_file and generated_filename and old_stored_filename != generated_filename:
        old_file_path = Path(current_app.config["ACHIEVEMENTS_UPLOAD_FOLDER"]) / old_stored_filename
        if old_file_path.is_file():
            old_file_path.unlink(missing_ok=True)

    flash("Achievement updated successfully.", "success")
    return redirect(url_for("main.achievements_page"))


@main.route("/achievements/<int:achievement_id>/delete", methods=["POST"])
@login_required
@roles_required("owner")
def delete_achievement(achievement_id: int):
    achievement = db.session.get(Achievement, achievement_id)
    if not achievement:
        abort(404)

    file_path = Path(current_app.config["ACHIEVEMENTS_UPLOAD_FOLDER"]) / achievement.stored_filename
    db.session.delete(achievement)
    db.session.commit()

    if file_path.is_file():
        file_path.unlink(missing_ok=True)

    flash("Achievement deleted successfully.", "success")
    return redirect(url_for("main.achievements_page"))


@main.route("/achievements/file/<int:achievement_id>")
def view_achievement_file(achievement_id: int):
    achievement = db.session.get(Achievement, achievement_id)
    if not achievement:
        abort(404)

    return send_from_directory(
        current_app.config["ACHIEVEMENTS_UPLOAD_FOLDER"],
        achievement.stored_filename,
        mimetype=achievement.mime_type,
        as_attachment=False,
        download_name=achievement.original_filename,
    )


@main.route("/admin/dashboard")
@main.route("/admin/members/manage")
@login_required
@roles_required("admin")
def admin_dashboard():
    users = (
        User.query.filter(User.role.in_(["admin", "user"]))
        .order_by(User.created_at.desc())
        .all()
    )
    focus_user_id = request.args.get("focus", type=int)
    scroll_position = request.args.get("scroll", type=int)
    return render_template(
        "admin_dashboard.html",
        users=users,
        focus_user_id=focus_user_id,
        scroll_position=scroll_position,
    )


@main.route("/admin/members/add")
@login_required
@roles_required("admin")
def admin_add_member_page():
    return render_template("admin_add_member.html")


@main.route("/admin/users/create", methods=["POST"])
@login_required
@roles_required("admin")
def create_member():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "user").strip().lower()

    _user, errors = create_user_account(username, email, password, role)
    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("main.admin_add_member_page"))

    flash("New member added successfully.", "success")
    return redirect(url_for("main.admin_add_member_page"))


@main.route("/admin/users/<int:user_id>/block", methods=["POST"])
@login_required
@roles_required("admin")
def temporary_block_user(user_id: int):
    user = get_admin_manageable_user(user_id)
    scroll_position = parse_scroll_position(request.form.get("scroll_y", ""))

    if user.id == current_user.id:
        flash("You cannot temporarily block your own account.", "warning")
        return redirect_to_admin_dashboard(
            focus_user_id=user.id,
            scroll_position=scroll_position,
        )

    minutes = parse_block_minutes(request.form.get("minutes", "30"))
    if minutes is None:
        flash("Invalid block duration. Choose between 1 and 1440 minutes.", "danger")
        return redirect_to_admin_dashboard(
            focus_user_id=user.id,
            scroll_position=scroll_position,
        )

    user.failed_login_attempts = 0
    user.lockout_until = utcnow_naive() + timedelta(minutes=minutes)
    db.session.commit()
    flash(f"Temporarily blocked {user.username} for {minutes} minute(s).", "success")
    return redirect_to_admin_dashboard(
        focus_user_id=user.id,
        scroll_position=scroll_position,
    )


@main.route("/admin/users/<int:user_id>/disable", methods=["POST"])
@login_required
@roles_required("admin")
def toggle_user_status(user_id: int):
    user = get_admin_manageable_user(user_id)
    scroll_position = parse_scroll_position(request.form.get("scroll_y", ""))

    action = request.form.get("action", "").strip().lower()
    if action not in {"disable", "enable"}:
        flash("Invalid account action.", "danger")
        return redirect_to_admin_dashboard(
            focus_user_id=user.id,
            scroll_position=scroll_position,
        )

    if user.id == current_user.id and action == "disable":
        flash("You cannot disable your own admin account.", "warning")
        return redirect_to_admin_dashboard(
            focus_user_id=user.id,
            scroll_position=scroll_position,
        )

    if action == "disable":
        user.is_active = False
        user.failed_login_attempts = 0
        user.lockout_until = None
        message = f"Disabled account for {user.username}."
    else:
        user.is_active = True
        message = f"Enabled account for {user.username}."

    db.session.commit()
    flash(message, "success")
    return redirect_to_admin_dashboard(
        focus_user_id=user.id,
        scroll_position=scroll_position,
    )


@main.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def delete_user(user_id: int):
    user = get_admin_manageable_user(user_id)
    scroll_position = parse_scroll_position(request.form.get("scroll_y", ""))

    if user.id == current_user.id:
        flash("You cannot delete your own admin account.", "warning")
        return redirect_to_admin_dashboard(
            focus_user_id=user.id,
            scroll_position=scroll_position,
        )

    username = user.username
    deleted_user_id = user.id
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted account for {username}.", "success")
    return redirect_to_admin_dashboard(
        focus_user_id=deleted_user_id,
        scroll_position=scroll_position,
    )


@main.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@roles_required("admin")
def update_user_role(user_id: int):
    user = get_admin_manageable_user(user_id)
    scroll_position = parse_scroll_position(request.form.get("scroll_y", ""))
    new_role = request.form.get("role", "").strip().lower()

    if new_role not in {"admin", "user"}:
        flash("Invalid role.", "danger")
        return redirect_to_admin_dashboard(
            focus_user_id=user.id,
            scroll_position=scroll_position,
        )

    if user.id == current_user.id and new_role != "admin":
        flash("You cannot remove your own admin role.", "warning")
        return redirect_to_admin_dashboard(
            focus_user_id=user.id,
            scroll_position=scroll_position,
        )

    user.role = new_role
    db.session.commit()
    flash(f"Updated role for {user.username}.", "success")
    return redirect_to_admin_dashboard(
        focus_user_id=user.id,
        scroll_position=scroll_position,
    )


@main.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
@login_required
@roles_required("admin")
def unlock_user(user_id: int):
    user = get_admin_manageable_user(user_id)
    scroll_position = parse_scroll_position(request.form.get("scroll_y", ""))
    user.failed_login_attempts = 0
    user.lockout_until = None
    db.session.commit()
    flash(f"Unlocked account for {user.username}.", "success")
    return redirect_to_admin_dashboard(
        focus_user_id=user.id,
        scroll_position=scroll_position,
    )
