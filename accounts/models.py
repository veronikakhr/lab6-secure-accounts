from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    blocked = models.BooleanField(default=False)
    failed_passwords = models.PositiveIntegerField(default=0)
    failed_second_factors = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    totp_secret = models.TextField(blank=True)
    last_totp_step = models.BigIntegerField(default=-1)
    google_subject = models.CharField(max_length=255, unique=True, null=True, blank=True)


class EmailToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    purpose = models.CharField(max_length=12)
    digest = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True)


class LoginEvent(models.Model):
    time = models.DateTimeField(auto_now_add=True, db_index=True)
    account = models.EmailField()
    ip = models.GenericIPAddressField(null=True)
    result = models.CharField(max_length=32)
