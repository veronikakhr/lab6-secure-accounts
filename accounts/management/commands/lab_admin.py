from getpass import getpass

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from accounts.models import User
from accounts.views import valid_email


class Command(BaseCommand):
    help = "Створити адміністратора лабораторної з підтвердженою електронною адресою."

    def add_arguments(self, parser):
        parser.add_argument("email")

    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        if not valid_email(email) or User.objects.filter(email=email).exists():
            raise CommandError("Введи коректну адресу, якої ще немає в базі.")
        password = getpass("Пароль адміністратора: ")
        if password != getpass("Повтори пароль: "):
            raise CommandError("Паролі не збігаються.")
        try:
            validate_password(password)
        except ValidationError as error:
            raise CommandError(error.messages[0]) from error
        User.objects.create_user(username=email, email=email, password=password, is_staff=True, email_verified=True)
        self.stdout.write(self.style.SUCCESS("Адміністратора створено."))
