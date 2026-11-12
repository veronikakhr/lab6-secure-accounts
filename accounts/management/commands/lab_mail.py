from email import policy
from email.parser import BytesParser

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Показати останній тестовий лист, збережений у локальній вихідній пошті."

    def handle(self, *args, **options):
        files = list(settings.EMAIL_FILE_PATH.glob("*.log"))
        if not files:
            raise CommandError("У локальній пошті ще немає листів.")
        with max(files, key=lambda path: path.stat().st_mtime_ns).open("rb") as message_file:
            message = BytesParser(policy=policy.default).parse(message_file)
        self.stdout.write(f"Кому: {message['To']}\nТема: {message['Subject']}")
        self.stdout.write(message.get_content().split("\n" + "-" * 79)[0].rstrip())
