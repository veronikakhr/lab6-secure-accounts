import base64
import hashlib
from io import BytesIO
import secrets
from datetime import timedelta

import pyotp
from PIL import Image, ImageDraw, ImageFont
from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import login
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import salted_hmac

from .models import EmailToken, LoginEvent, User


class PasswordPolicy:
    def validate(self, password, user=None):
        if not (
            8 <= len(password) <= 128
            and any(char.isupper() for char in password)
            and any(char.islower() for char in password)
            and any(char.isdecimal() for char in password)
            and any(not char.isalnum() and not char.isspace() for char in password)
        ):
            raise ValidationError(self.get_help_text(), code="password_policy")

    def get_help_text(self):
        return "Пароль має містити 8–128 символів, велику й малу літери, цифру та спеціальний символ."


def new_captcha(request):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    challenge = "".join(secrets.choice(alphabet) for _ in range(6))
    request.session["captcha"] = challenge
    image = Image.new("RGB", (246, 66), "#eef2fa")
    draw = ImageDraw.Draw(image)
    for _ in range(48):
        x, y = secrets.randbelow(246), secrets.randbelow(66)
        draw.ellipse((x, y, x + 3, y + 3), fill="#8496b3")
    font = ImageFont.load_default(size=35)
    for index, char in enumerate(challenge):
        draw.text((14 + 37 * index, 5 + secrets.randbelow(11)), char, font=font, fill="#13243d")
    for _ in range(4):
        draw.line((0, secrets.randbelow(66), 246, secrets.randbelow(66)), fill="#8496b3")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def captcha_matches(request, answer):
    expected = request.session.pop("captcha", "")
    return bool(expected) and secrets.compare_digest(expected.encode(), answer.strip().upper().encode())


def digest_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def send_token(user, purpose):
    raw = secrets.token_urlsafe(32)
    lifetime = timedelta(hours=24) if purpose == "activate" else timedelta(minutes=30)
    title = "Активація облікового запису" if purpose == "activate" else "Відновлення пароля"
    url = settings.APP_BASE_URL + reverse(purpose, args=[raw])
    EmailToken.objects.create(
        user=user, purpose=purpose, digest=digest_token(raw), expires_at=timezone.now() + lifetime,
    )
    send_mail(title, f"{title}\n\n{url}\n\nПосилання одноразове.", None, [user.email])


def valid_tokens(raw, purpose):
    return EmailToken.objects.filter(
        digest=digest_token(raw), purpose=purpose, expires_at__gt=timezone.now(), used_at=None,
    )


@transaction.atomic
def consume_token(raw, purpose, password=None):
    tokens = valid_tokens(raw, purpose)
    token = tokens.first()
    if token is None or tokens.update(used_at=timezone.now()) != 1:
        return False
    user = token.user
    if purpose == "activate":
        user.email_verified = True
        user.save(update_fields=["email_verified"])
    else:
        user.set_password(password)
        user.save(update_fields=["password"])
        EmailToken.objects.filter(user=user, purpose="reset", used_at=None).update(used_at=timezone.now())
    return True


def restricted(user):
    return user.blocked or bool(user.locked_until and user.locked_until > timezone.now())


def record(request, email, result):
    LoginEvent.objects.create(account=email, ip=request.META.get("REMOTE_ADDR") or None, result=result)


def start_login(request, user, method):
    if user.totp_secret:
        request.session.cycle_key()
        request.session["pending_login"] = {
            "user": user.pk, "expires": int(timezone.now().timestamp()) + 300,
            "method": method,
        }
        return "second_factor"
    finish_login(request, user, method)
    return "profile"


def finish_login(request, user, method):
    request.session.pop("pending_login", None)
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    record(request, user.email, f"success:{method}")


def totp_cipher():
    key = salted_hmac("accounts.totp", "v1", algorithm="sha256").digest()
    return Fernet(base64.urlsafe_b64encode(key))


def matching_totp_step(secret, code):
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int(timezone.now().timestamp()) // totp.interval
    for step in (current, current - 1, current + 1):
        if secrets.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def verify_totp(user, code):
    secret = totp_cipher().decrypt(user.totp_secret.encode()).decode()
    step = matching_totp_step(secret, code)
    return step is not None and User.objects.filter(
        pk=user.pk, totp_secret=user.totp_secret, last_totp_step__lt=step,
    ).update(last_totp_step=step) == 1
