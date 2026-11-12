import base64
import logging
from datetime import timedelta
from io import BytesIO

import pyotp
import qrcode
import qrcode.image.svg
from authlib.integrations.django_client import OAuth
from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Case, DateTimeField, F, Value, When
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from .models import LoginEvent, User
from .security import (
    captcha_matches, consume_token, finish_login, matching_totp_step, new_captcha,
    record, restricted, send_token, start_login, totp_cipher, valid_tokens, verify_totp,
)

logger = logging.getLogger(__name__)
oauth = OAuth()
if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
    oauth.register(
        "google",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
    )

DUMMY_PASSWORD = make_password("unused-login-timing-value")
FORM_METHODS = ["GET", "POST"]


def render_form(request, title, fields=(), **extra):
    return render(request, "accounts/form.html", {
        "title": title, "fields": fields, **extra,
    })


def email_value(request):
    return request.POST.get("email", "").strip().lower()


def valid_email(email):
    try:
        forms.EmailField(max_length=150).clean(email)
    except ValidationError:
        return False
    return True


def password_error(password):
    try:
        validate_password(password)
    except ValidationError as error:
        return error.messages[0]
    return ""


def show_home(request):
    return render(request, "accounts/home.html")


@require_http_methods(FORM_METHODS)
@never_cache
def register(request):
    email = email_value(request)
    error = ""
    if request.method == "POST":
        password = request.POST.get("password", "")
        solved = captcha_matches(request, request.POST.get("captcha", ""))
        error = password_error(password)
        if not error and not valid_email(email):
            error = "Вкажи коректну електронну адресу."
        if not error and not solved:
            error = "Символи CAPTCHA введено неправильно."
        if not error:
            try:
                with transaction.atomic():
                    user = User.objects.create_user(username=email, email=email, password=password)
                    send_token(user, "activate")
            except IntegrityError:
                error = "Ця адреса вже зареєстрована."
            else:
                messages.success(request, "Акаунт створено. Відкрий лист для активації.")
                return redirect("login")
    return render_form(request, "Реєстрація", [
        ("email", "Електронна пошта", "email", email),
        ("password", "Пароль", "password", ""),
        ("captcha", "Символи з картинки", "text", ""),
    ], error=error, captcha=new_captcha(request), button="Зареєструватися")


@require_http_methods(FORM_METHODS)
@never_cache
def activate(request, token):
    if request.method == "POST" and consume_token(token, "activate"):
        messages.success(request, "Електронну адресу підтверджено. Тепер можна увійти.")
        return redirect("login")
    if not valid_tokens(token, "activate").exists():
        return render_form(request, "Активація", error="Посилання прострочене або вже використане.")
    return render_form(request, "Активація", button="Підтвердити електронну адресу")


@require_http_methods(FORM_METHODS)
@never_cache
def sign_in(request):
    if request.user.is_authenticated:
        return redirect("profile")
    email = email_value(request)
    error = ""
    if request.method == "POST":

        request.session.pop("pending_login", None)
        user = User.objects.filter(email=email).first() if valid_email(email) else None
        password = request.POST.get("password", "")
        if user and restricted(user):
            record(request, email, "blocked")
            error = "Вхід заблоковано. Звернися до адміністратора або спробуй пізніше."
        elif not user or len(password) > 128 or not user.check_password(password):
            if not user and len(password) <= 128:
                check_password(password, DUMMY_PASSWORD)
            error = "Неправильна пошта або пароль."
            result = "invalid_password"
            if user:
                now = timezone.now()
                clear_expired_lock(user)
                User.objects.filter(pk=user.pk, locked_until=None, blocked=False).update(
                    failed_passwords=F("failed_passwords") + 1,
                    locked_until=Case(
                        When(failed_passwords__gte=4, then=Value(now + timedelta(minutes=5))),
                        default=Value(None), output_field=DateTimeField(),
                    ),
                )
                user.refresh_from_db()
                if restricted(user):
                    error = "Вхід тимчасово заблоковано після 5 невдалих спроб."
                    result = "locked"
            if valid_email(email):
                record(request, email, result)
        elif not user.email_verified:
            record(request, email, "unverified")
            error = "Спочатку активуй акаунт за посиланням із листа."
        else:
            reset_failures(user)
            return redirect(start_login(request, user, "password"))
    return render_form(request, "Вхід", [
        ("email", "Електронна пошта", "email", email),
        ("password", "Пароль", "password", ""),
    ], error=error, button="Увійти", login_links=True, google=bool(oauth.create_client("google")))


def reset_failures(user):
    clear_expired_lock(user)
    User.objects.filter(pk=user.pk, blocked=False, locked_until=None).update(failed_passwords=0)


def clear_expired_lock(user):
    User.objects.filter(pk=user.pk, locked_until__lte=timezone.now()).update(
        failed_passwords=0, failed_second_factors=0, locked_until=None,
    )


@require_http_methods(FORM_METHODS)
@never_cache
def second_factor(request):
    pending = request.session.get("pending_login")
    if not pending or pending["expires"] <= int(timezone.now().timestamp()):
        request.session.pop("pending_login", None)
        return redirect("login")
    user = User.objects.filter(pk=pending["user"], email_verified=True).first()
    if not user or restricted(user) or not user.totp_secret:
        request.session.pop("pending_login", None)
        return redirect("login")
    error = ""
    if request.method == "POST":
        if verify_totp(user, request.POST.get("code", "").strip()):
            clear_expired_lock(user)
            User.objects.filter(pk=user.pk, locked_until=None).update(failed_second_factors=0)
            finish_login(request, user, pending["method"])
            return redirect("profile")
        record(request, user.email, "invalid_2fa")
        clear_expired_lock(user)
        User.objects.filter(pk=user.pk, blocked=False, locked_until=None).update(
            failed_second_factors=F("failed_second_factors") + 1,
            locked_until=Case(
                When(failed_second_factors__gte=4, then=Value(timezone.now() + timedelta(minutes=5))),
                default=Value(None), output_field=DateTimeField(),
            ),
        )
        user.refresh_from_db()
        if restricted(user):
            record(request, user.email, "locked_2fa")
            request.session.pop("pending_login", None)
            messages.error(request, "Забагато невдалих кодів. Вхід тимчасово заблоковано.")
            return redirect("login")
        error = "Код неправильний, прострочений або вже використаний."
    return render_form(request, "Двофакторна автентифікація", [
        ("code", "Шестизначний код", "text", ""),
    ], error=error, button="Підтвердити вхід")


@login_required
@never_cache
def profile(request):
    return render(request, "accounts/profile.html")


@require_POST
def sign_out(request):
    logout(request)
    return redirect("home")


@login_required
@require_http_methods(FORM_METHODS)
@never_cache
def enable_2fa(request):
    if request.user.totp_secret:
        return redirect("profile")
    secret = request.session.get("totp_setup")
    if request.method == "GET" or not secret:
        secret = pyotp.random_base32()
        request.session["totp_setup"] = secret
    error = ""
    if request.method == "POST":
        step = matching_totp_step(secret, request.POST.get("code", "").strip())
        if step is not None:
            User.objects.filter(pk=request.user.pk, totp_secret="").update(
                totp_secret=totp_cipher().encrypt(secret.encode()).decode(), last_totp_step=step,
            )
            request.session.pop("totp_setup", None)
            messages.success(request, "Двофакторну автентифікацію увімкнено.")
            return redirect("profile")
        error = "Перевір код у застосунку автентифікації."
    uri = pyotp.TOTP(secret).provisioning_uri(name=request.user.email, issuer_name="Історія України")
    qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=6)
    buffer = BytesIO()
    qr.save(buffer)
    return render_form(request, "Увімкнення 2FA", [
        ("code", "Код із застосунку", "text", ""),
    ], qr=base64.b64encode(buffer.getvalue()).decode(), error=error, button="Увімкнути 2FA")


@login_required
@require_http_methods(FORM_METHODS)
@never_cache
def disable_2fa(request):
    if not request.user.totp_secret:
        return redirect("profile")
    error = ""
    if request.method == "POST":
        if verify_totp(request.user, request.POST.get("code", "").strip()):
            User.objects.filter(pk=request.user.pk, totp_secret=request.user.totp_secret).update(
                totp_secret="", last_totp_step=-1,
            )
            messages.success(request, "Двофакторну автентифікацію вимкнено.")
            return redirect("profile")
        error = "Введи новий код із застосунку автентифікації."
    return render_form(request, "Вимкнення 2FA", [
        ("code", "Шестизначний код", "text", ""),
    ], error=error, button="Вимкнути 2FA")


@require_http_methods(FORM_METHODS)
@never_cache
def forgot(request):
    if request.method == "POST":
        email = email_value(request)
        user = User.objects.filter(email=email, email_verified=True).first() if valid_email(email) else None
        if user and user.has_usable_password() and not user.blocked:
            send_token(user, "reset")
        messages.success(request, "Якщо адреса прив’язана до активного акаунта з паролем, надіслано лист.")
        return redirect("login")
    return render_form(request, "Відновлення пароля", [
        ("email", "Електронна пошта", "email", ""),
    ], button="Надіслати посилання")


@require_http_methods(FORM_METHODS)
@never_cache
def reset(request, token):
    if not valid_tokens(token, "reset").exists():
        return render_form(request, "Новий пароль", error="Посилання прострочене або вже використане.")
    error = ""
    if request.method == "POST":
        password = request.POST.get("password", "")
        error = password_error(password)
        if not error and consume_token(token, "reset", password):
            messages.success(request, "Пароль змінено. Увійди з новим паролем.")
            return redirect("login")
        error = error or "Посилання прострочене або вже використане."
    return render_form(request, "Новий пароль", [
        ("password", "Новий пароль", "password", ""),
    ], error=error, button="Зберегти пароль")


def require_staff(request):
    if not request.user.is_staff:
        raise PermissionDenied


@login_required
@never_cache
def dashboard(request):
    require_staff(request)
    return render(request, "accounts/dashboard.html", {
        "users": User.objects.order_by("email"),
        "events": LoginEvent.objects.order_by("-time", "-pk")[:100],
    })


@login_required
@require_POST
def change_account(request, pk, action):
    require_staff(request)
    if action not in ("block", "unblock"):
        raise Http404
    target = get_object_or_404(User, pk=pk, is_staff=False)
    target.blocked = action == "block"
    target.locked_until = None
    target.failed_passwords = 0
    target.failed_second_factors = 0
    target.save(update_fields=["blocked", "locked_until", "failed_passwords", "failed_second_factors"])
    messages.success(request, "Статус акаунта оновлено.")
    return redirect("dashboard")


def google_start(request):
    client = oauth.create_client("google")
    if not client:
        raise Http404
    if request.user.is_authenticated:
        return redirect("profile")
    return client.authorize_redirect(request, settings.APP_BASE_URL + reverse("google_callback"))


@never_cache
def google_callback(request):
    client = oauth.create_client("google")
    if not client:
        raise Http404
    if request.user.is_authenticated:
        return redirect("profile")
    try:
        claims = client.authorize_access_token(request)["userinfo"]
    except Exception as error:
        logger.warning("Google OIDC callback failed (%s)", type(error).__name__)
        messages.error(request, "Не вдалося підтвердити вхід через Google.")
        return redirect("login")
    subject, email = claims.get("sub"), str(claims.get("email", "")).lower()
    if not subject or not claims.get("email_verified") or not valid_email(email):
        messages.error(request, "Google не підтвердив електронну адресу.")
        return redirect("login")
    user = User.objects.filter(google_subject=subject).first()
    if not user:
        try:
            user = User.objects.create_user(
                username=email, email=email, email_verified=True, google_subject=subject,
            )
        except IntegrityError:
            messages.error(request, "Для цієї адреси вже існує акаунт. Скористайся його способом входу.")
            return redirect("login")
    if restricted(user):
        record(request, user.email, "blocked:google")
        messages.error(request, "Вхід до акаунта заблоковано.")
        return redirect("login")
    return redirect(start_login(request, user, "google"))
