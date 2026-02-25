import random
import re
from functools import wraps

from flask import abort
from flask_login import current_user

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.fullmatch(email.strip()))


def is_valid_username(username: str) -> bool:
    return bool(USERNAME_REGEX.fullmatch(username.strip()))


def is_strong_password(password: str) -> bool:
    """
    Password policy:
    - At least 12 chars
    - Upper + lower + digit + special char
    """
    if len(password) < 12:
        return False
    checks = [
        re.search(r"[A-Z]", password),
        re.search(r"[a-z]", password),
        re.search(r"[0-9]", password),
        re.search(r"[^A-Za-z0-9]", password),
    ]
    return all(checks)


def generate_captcha() -> tuple[str, str]:
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    operator = random.choice(["+", "-"])

    if operator == "-" and b > a:
        a, b = b, a

    answer = str(a + b if operator == "+" else a - b)
    question = f"What is {a} {operator} {b}?"
    return question, answer


def roles_required(*allowed_roles: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in allowed_roles:
                abort(403)
            return func(*args, **kwargs)

        return wrapper

    return decorator
