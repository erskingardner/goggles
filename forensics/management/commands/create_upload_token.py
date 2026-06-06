from django.core.management.base import BaseCommand, CommandParser

from forensics.models import UploadToken


class Command(BaseCommand):
    help = "Create a bearer token for forensic dump uploads."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("name", help="Human-friendly token name, e.g. 'ios qa device'")

    def handle(self, *args, **options):
        raw_token, token = UploadToken.issue(options["name"])
        self.stdout.write(f"Created upload token {token.name} ({token.token_prefix})")
        self.stdout.write("Store this token now; it will not be shown again:")
        self.stdout.write(raw_token)
