""" Deceptive Author Detector

Detects when an author is using a disposable email
"""

from guarddog.analyzer.metadata.deceptive_author import DeceptiveAuthorDetector

from .utils import get_email_addresses


class MavenDeceptiveAuthor(DeceptiveAuthorDetector):
    def get_email_addresses(self, package_info: dict):
        return get_email_addresses(package_info)
