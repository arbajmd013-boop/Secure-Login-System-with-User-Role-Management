import base64
from io import BytesIO
from pathlib import Path

from app.extensions import db
from app.models import Achievement, User

PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/w8AAusB9Y3hR1EAAAAASUVORK5CYII="
)

OWNER_EMAIL = "owner123@gmail.com"
OWNER_PASSWORD = "Ownerpassword1234@@##$$"


def get_captcha_answer(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("captcha_answer")


def login(client, email, password):
    captcha_answer = get_captcha_answer(client)
    return client.post(
        "/login",
        data={
            "email": email,
            "password": password,
            "captcha_answer": captcha_answer,
        },
        follow_redirects=True,
    )


def login_owner(client):
    return login(client, OWNER_EMAIL, OWNER_PASSWORD)


def image_upload(filename: str = "proof.png"):
    return BytesIO(PNG_1PX), filename


def test_registration_success(client):
    response = client.post(
        "/register",
        data={
            "username": "new_user",
            "email": "new@example.com",
            "password": "NewSecurePass1!",
            "confirm_password": "NewSecurePass1!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Registration successful" in response.data


def test_public_registration_cannot_create_admin(client, app):
    response = client.post(
        "/register",
        data={
            "username": "tampered_role_user",
            "email": "tampered@example.com",
            "password": "TamperPass123!",
            "confirm_password": "TamperPass123!",
            "role": "admin",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Registration successful" in response.data

    with app.app_context():
        user = User.query.filter_by(email="tampered@example.com").first()
        assert user is not None
        assert user.role == "user"


def test_duplicate_registration_blocked(client):
    response = client.post(
        "/register",
        data={
            "username": "normal_user",
            "email": "user@example.com",
            "password": "AnotherPass1!",
            "confirm_password": "AnotherPass1!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"already exists" in response.data


def test_registration_password_confirm_mismatch_blocked(client, app):
    response = client.post(
        "/register",
        data={
            "username": "mismatch_user",
            "email": "mismatch@example.com",
            "password": "MismatchPass123!",
            "confirm_password": "DifferentPass123!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Password and Re-enter Password must match" in response.data

    with app.app_context():
        user = User.query.filter_by(email="mismatch@example.com").first()
        assert user is None


def test_login_and_register_pages_show_password_toggle(client):
    login_page = client.get("/login")
    register_page = client.get("/register")

    assert login_page.status_code == 200
    assert register_page.status_code == 200
    assert b"password-toggle" in login_page.data
    assert b"name=\"confirm_password\"" in register_page.data
    assert register_page.data.count(b"password-toggle") >= 2


def test_login_success(client):
    response = login(client, "user@example.com", "UserPass123!!")

    assert response.status_code == 200
    assert b"User Dashboard" in response.data


def test_owner_login_redirects_to_achievements(client):
    response = login_owner(client)

    assert response.status_code == 200
    assert b"Hall Of Fame & Bounty Posts" in response.data
    assert b"Owner Upload Panel" in response.data


def test_public_pages_are_accessible_pre_login(client):
    home = client.get("/")
    achievements = client.get("/achievements")
    achievements_alias = client.get("/achevement")
    contact = client.get("/contact")

    assert home.status_code == 200
    assert achievements.status_code == 200
    assert achievements_alias.status_code == 200
    assert contact.status_code == 200


def test_favicon_route_is_available(client):
    response = client.get("/favicon.ico")

    assert response.status_code == 200
    assert len(response.data) > 0
    assert response.content_type.startswith("image/")


def test_public_home_page_shows_profile_intro(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"About Me" in response.data
    assert b"MD ARBAJ ANSARI" in response.data
    assert b"arbajmd013@gmail.com" in response.data


def test_public_contact_page_shows_details(client):
    response = client.get("/contact")

    assert response.status_code == 200
    assert b"Contact Us" in response.data
    assert b"arbajmd013@gmail.com" in response.data


def test_owner_can_upload_hall_of_fame_with_event_date(client, app):
    login_owner(client)

    response = client.post(
        "/achievements/upload",
        data={
            "category": "hall_of_fame",
            "title": "Bugcrowd Hall Of Fame",
            "description": "Valid finding acknowledged.",
            "achieved_on": "2025-12-10",
            "proof_file": image_upload("hof.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Achievement uploaded successfully" in response.data
    assert b"Bugcrowd Hall Of Fame" in response.data

    with app.app_context():
        achievement = Achievement.query.filter_by(title="Bugcrowd Hall Of Fame").first()
        assert achievement is not None
        assert achievement.category == "hall_of_fame"
        assert str(achievement.event_date) == "2025-12-10"


def test_uploaded_file_can_be_served_by_id(client, app):
    login_owner(client)
    client.post(
        "/achievements/upload",
        data={
            "category": "bounty_post",
            "title": "HackerOne Report",
            "description": "Bounty proof",
            "proof_file": image_upload("report.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        achievement = Achievement.query.filter_by(title="HackerOne Report").first()
        achievement_id = achievement.id

    response = client.get(f"/achievements/file/{achievement_id}")
    assert response.status_code == 200
    assert response.mimetype == "image/png"


def test_owner_can_delete_achievement(client, app):
    login_owner(client)
    client.post(
        "/achievements/upload",
        data={
            "category": "bounty_post",
            "title": "Delete Me",
            "description": "remove",
            "proof_file": image_upload("deleteme.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        achievement = Achievement.query.filter_by(title="Delete Me").first()
        achievement_id = achievement.id
        file_path = (
            Path(app.config["ACHIEVEMENTS_UPLOAD_FOLDER"]) / achievement.stored_filename
        )

    assert file_path.exists()

    response = client.post(
        f"/achievements/{achievement_id}/delete",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Achievement deleted successfully" in response.data

    with app.app_context():
        deleted = db.session.get(Achievement, achievement_id)
        assert deleted is None

    assert not file_path.exists()


def test_owner_can_edit_achievement_and_replace_file(client, app):
    login_owner(client)
    client.post(
        "/achievements/upload",
        data={
            "category": "hall_of_fame",
            "title": "Editable Entry",
            "description": "Initial description",
            "achieved_on": "2026-01-01",
            "proof_file": image_upload("initial.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        achievement = Achievement.query.filter_by(title="Editable Entry").first()
        achievement_id = achievement.id
        old_stored_filename = achievement.stored_filename
        old_file_path = Path(app.config["ACHIEVEMENTS_UPLOAD_FOLDER"]) / old_stored_filename

    response = client.post(
        f"/achievements/{achievement_id}/edit",
        data={
            "category": "bounty_post",
            "title": "Edited Entry",
            "description": "Updated description",
            "achieved_on": "2026-02-01",
            "proof_file": image_upload("updated.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Achievement updated successfully" in response.data

    with app.app_context():
        updated = db.session.get(Achievement, achievement_id)
        assert updated is not None
        assert updated.title == "Edited Entry"
        assert updated.category == "bounty_post"
        assert updated.description == "Updated description"
        assert str(updated.event_date) == "2026-02-01"
        assert updated.stored_filename != old_stored_filename
        new_file_path = Path(app.config["ACHIEVEMENTS_UPLOAD_FOLDER"]) / updated.stored_filename

    assert new_file_path.exists()
    assert not old_file_path.exists()


def test_admin_cannot_upload_achievement(client):
    login(client, "admin@example.com", "AdminPass123!")
    response = client.post(
        "/achievements/upload",
        data={
            "category": "bounty_post",
            "title": "Should Fail",
            "description": "No owner role",
            "proof_file": image_upload("proof.png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 403


def test_user_cannot_upload_achievement(client):
    login(client, "user@example.com", "UserPass123!!")
    response = client.post(
        "/achievements/upload",
        data={
            "category": "bounty_post",
            "title": "Should Fail",
            "description": "No owner role",
            "proof_file": image_upload("proof.png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 403


def test_upload_rejects_disallowed_file_type(client, app):
    login_owner(client)
    response = client.post(
        "/achievements/upload",
        data={
            "category": "bounty_post",
            "title": "Invalid File",
            "description": "Should be blocked",
            "proof_file": (BytesIO(b"<?php echo 'x'; ?>"), "payload.php"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Only PNG/JPG/JPEG/WEBP/GIF/PDF files are allowed" in response.data

    with app.app_context():
        blocked = Achievement.query.filter_by(title="Invalid File").first()
        assert blocked is None


def test_upload_rejects_signature_mismatch(client, app):
    login_owner(client)
    response = client.post(
        "/achievements/upload",
        data={
            "category": "hall_of_fame",
            "title": "Fake PNG",
            "description": "Spoof attempt",
            "proof_file": (BytesIO(b"<?php echo 'not-image'; ?>"), "fake.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"File content does not match the selected file type" in response.data

    with app.app_context():
        blocked = Achievement.query.filter_by(title="Fake PNG").first()
        assert blocked is None


def test_owner_can_update_about_and_contact_content(client):
    login_owner(client)

    about_response = client.post(
        "/owner/content/about",
        data={
            "about_text": (
                "I am MD ARBAJ ANSARI, focused on practical security testing, "
                "responsible disclosure, and secure software engineering practices."
            ),
        },
        follow_redirects=True,
    )

    assert about_response.status_code == 200
    assert b"About content updated" in about_response.data

    contact_response = client.post(
        "/owner/content/contact",
        data={
            "contact_name": "MD ARBAJ ANSARI",
            "contact_email": "arbajmd013@gmail.com",
        },
        follow_redirects=True,
    )

    assert contact_response.status_code == 200
    assert b"Contact details updated" in contact_response.data


def test_admin_cannot_update_owner_content(client):
    login(client, "admin@example.com", "AdminPass123!")

    about_response = client.post(
        "/owner/content/about",
        data={"about_text": "A" * 60},
    )
    contact_response = client.post(
        "/owner/content/contact",
        data={"contact_name": "X", "contact_email": "x@example.com"},
    )

    assert about_response.status_code == 403
    assert contact_response.status_code == 403


def test_user_cannot_update_owner_content(client):
    login(client, "user@example.com", "UserPass123!!")

    about_response = client.post(
        "/owner/content/about",
        data={"about_text": "A" * 60},
    )
    contact_response = client.post(
        "/owner/content/contact",
        data={"contact_name": "X", "contact_email": "x@example.com"},
    )

    assert about_response.status_code == 403
    assert contact_response.status_code == 403


def test_non_owner_cannot_delete_achievement(client, app):
    login_owner(client)
    client.post(
        "/achievements/upload",
        data={
            "category": "hall_of_fame",
            "title": "Cannot Delete",
            "description": "owner only",
            "proof_file": image_upload("cannotdelete.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        achievement = Achievement.query.filter_by(title="Cannot Delete").first()
        achievement_id = achievement.id

    client.post("/logout", follow_redirects=True)
    login(client, "admin@example.com", "AdminPass123!")

    response = client.post(f"/achievements/{achievement_id}/delete")
    assert response.status_code == 403


def test_non_owner_cannot_edit_achievement(client, app):
    login_owner(client)
    client.post(
        "/achievements/upload",
        data={
            "category": "hall_of_fame",
            "title": "Cannot Edit",
            "description": "owner only",
            "proof_file": image_upload("cannotedit.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        achievement = Achievement.query.filter_by(title="Cannot Edit").first()
        achievement_id = achievement.id

    client.post("/logout", follow_redirects=True)
    login(client, "admin@example.com", "AdminPass123!")

    response = client.post(
        f"/achievements/{achievement_id}/edit",
        data={
            "category": "bounty_post",
            "title": "Malicious Edit",
            "description": "should not work",
        },
        follow_redirects=True,
    )

    assert response.status_code == 403

    with app.app_context():
        unchanged = db.session.get(Achievement, achievement_id)
        assert unchanged.title == "Cannot Edit"


def test_admin_dashboard_requires_admin(client):
    login(client, "user@example.com", "UserPass123!!")
    response = client.get("/admin/dashboard")

    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_admin_add_member_page_requires_admin(client):
    login(client, "user@example.com", "UserPass123!!")
    response = client.get("/admin/members/add")

    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_owner_cannot_access_admin_member_pages(client):
    login_owner(client)

    dashboard = client.get("/admin/dashboard")
    add_page = client.get("/admin/members/add")

    assert dashboard.status_code == 403
    assert add_page.status_code == 403


def test_admin_add_and_moderation_pages_are_separate(client):
    login(client, "admin@example.com", "AdminPass123!")

    add_page = client.get("/admin/members/add")
    moderation_page = client.get("/admin/dashboard")

    assert add_page.status_code == 200
    assert moderation_page.status_code == 200
    assert b'id="admin-create-form"' in add_page.data
    assert b'id="admin-create-form"' not in moderation_page.data
    assert b"Account Moderation" in moderation_page.data


def test_members_page_visible_to_user_and_owner_hidden(client):
    login(client, "user@example.com", "UserPass123!!")
    response = client.get("/members")

    assert response.status_code == 200
    assert b"Admin Members" in response.data
    assert b"User Members" in response.data
    assert b"admin_user" in response.data
    assert b"normal_user" in response.data
    assert b"owner123@gmail.com" not in response.data


def test_admin_dashboard_hides_owner_account(client):
    login(client, "admin@example.com", "AdminPass123!")
    response = client.get("/admin/dashboard")

    assert response.status_code == 200
    assert b"owner123@gmail.com" not in response.data


def test_user_cannot_create_member_via_admin_endpoint(client, app):
    login(client, "user@example.com", "UserPass123!!")
    response = client.post(
        "/admin/users/create",
        data={
            "username": "blocked_user",
            "email": "blocked@example.com",
            "password": "BlockedPass123!",
            "role": "user",
        },
    )

    assert response.status_code == 403

    with app.app_context():
        blocked = User.query.filter_by(email="blocked@example.com").first()
        assert blocked is None


def test_admin_can_create_admin_member(client, app):
    login(client, "admin@example.com", "AdminPass123!")
    response = client.post(
        "/admin/users/create",
        data={
            "username": "new_admin",
            "email": "new_admin@example.com",
            "password": "NewAdminPass123!",
            "role": "admin",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"New member added successfully" in response.data

    with app.app_context():
        created = User.query.filter_by(email="new_admin@example.com").first()
        assert created is not None
        assert created.role == "admin"


def test_user_cannot_change_role_via_idor(client, app):
    login(client, "user@example.com", "UserPass123!!")

    with app.app_context():
        target = User.query.filter_by(email="admin@example.com").first()
        target_id = target.id

    response = client.post(
        f"/admin/users/{target_id}/role",
        data={"role": "user"},
    )
    assert response.status_code == 403

    with app.app_context():
        unchanged = db.session.get(User, target_id)
        assert unchanged.role == "admin"


def test_admin_cannot_manage_owner_by_id(client, app):
    login(client, "admin@example.com", "AdminPass123!")

    with app.app_context():
        owner = User.query.filter_by(email=OWNER_EMAIL).first()
        owner_id = owner.id

    assert client.post(f"/admin/users/{owner_id}/block", data={"minutes": "10"}).status_code == 403
    assert (
        client.post(
            f"/admin/users/{owner_id}/disable",
            data={"action": "disable"},
        ).status_code
        == 403
    )
    assert client.post(f"/admin/users/{owner_id}/role", data={"role": "user"}).status_code == 403
    assert client.post(f"/admin/users/{owner_id}/unlock").status_code == 403
    assert client.post(f"/admin/users/{owner_id}/delete").status_code == 403


def test_user_cannot_access_admin_moderation_endpoints(client, app):
    login(client, "user@example.com", "UserPass123!!")

    with app.app_context():
        target = User.query.filter_by(email="admin@example.com").first()
        target_id = target.id

    assert client.post(f"/admin/users/{target_id}/block", data={"minutes": "10"}).status_code == 403
    assert (
        client.post(
            f"/admin/users/{target_id}/disable",
            data={"action": "disable"},
        ).status_code
        == 403
    )
    assert client.post(f"/admin/users/{target_id}/delete").status_code == 403


def test_admin_can_temporary_block_user(client, app):
    login(client, "admin@example.com", "AdminPass123!")

    with app.app_context():
        target = User.query.filter_by(email="user@example.com").first()
        target_id = target.id

    response = client.post(
        f"/admin/users/{target_id}/block",
        data={"minutes": "45"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Temporarily blocked" in response.data

    client.post("/logout", follow_redirects=True)
    blocked_login = login(client, "user@example.com", "UserPass123!!")
    assert b"Account locked" in blocked_login.data


def test_admin_can_disable_and_enable_user(client, app):
    login(client, "admin@example.com", "AdminPass123!")

    with app.app_context():
        target = User.query.filter_by(email="user@example.com").first()
        target_id = target.id

    disable_response = client.post(
        f"/admin/users/{target_id}/disable",
        data={"action": "disable"},
        follow_redirects=True,
    )
    assert disable_response.status_code == 200
    assert b"Disabled account" in disable_response.data

    client.post("/logout", follow_redirects=True)
    disabled_login = login(client, "user@example.com", "UserPass123!!")
    assert b"Account disabled by admin" in disabled_login.data

    login(client, "admin@example.com", "AdminPass123!")
    enable_response = client.post(
        f"/admin/users/{target_id}/disable",
        data={"action": "enable"},
        follow_redirects=True,
    )
    assert enable_response.status_code == 200
    assert b"Enabled account" in enable_response.data

    client.post("/logout", follow_redirects=True)
    enabled_login = login(client, "user@example.com", "UserPass123!!")
    assert b"User Dashboard" in enabled_login.data


def test_admin_can_delete_user(client, app):
    login(client, "admin@example.com", "AdminPass123!")

    with app.app_context():
        target = User.query.filter_by(email="user@example.com").first()
        target_id = target.id

    response = client.post(
        f"/admin/users/{target_id}/delete",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Deleted account" in response.data

    with app.app_context():
        deleted_user = db.session.get(User, target_id)
        assert deleted_user is None

    client.post("/logout", follow_redirects=True)
    deleted_login = login(client, "user@example.com", "UserPass123!!")
    assert b"Invalid credentials" in deleted_login.data


def test_login_sqli_attempt_rejected(client):
    captcha_answer = get_captcha_answer(client)
    response = client.post(
        "/login",
        data={
            "email": "' OR '1'='1",
            "password": "anything",
            "captcha_answer": captcha_answer,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Invalid credentials" in response.data


def test_lockout_after_multiple_failed_attempts(client, app):
    for _ in range(3):
        response = login(client, "user@example.com", "wrong-password")

    assert response.status_code == 200
    assert b"Account locked" in response.data

    with app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        assert user is not None
        assert user.lockout_until is not None


def test_admin_can_unlock_user(client, app):
    for _ in range(3):
        login(client, "user@example.com", "wrong-password")

    login(client, "admin@example.com", "AdminPass123!")

    with app.app_context():
        locked_user = User.query.filter_by(email="user@example.com").first()
        user_id = locked_user.id

    response = client.post(f"/admin/users/{user_id}/unlock", follow_redirects=True)
    assert response.status_code == 200
    assert b"Unlocked account" in response.data

    with app.app_context():
        unlocked_user = db.session.get(User, user_id)
        assert unlocked_user.lockout_until is None
        assert unlocked_user.failed_login_attempts == 0
