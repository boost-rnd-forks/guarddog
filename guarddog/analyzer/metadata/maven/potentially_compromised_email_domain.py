"""Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""

from datetime import datetime
from typing import Optional

from guarddog.analyzer.metadata.potentially_compromised_email_domain import (
    PotentiallyCompromisedEmailDomainDetector,
)


class MavenPotentiallyCompromisedEmailDomainDetector(
    PotentiallyCompromisedEmailDomainDetector
):
    def __init__(self):
        super().__init__("maven")

    def get_email_addresses(self, package_info: dict):
        return package_info["info"]["email"]

    def get_project_latest_release_date(self, package_info) -> Optional[datetime]:
        """
        Gets the most recent release date of a Maven project
        Returns:
            datetime: creation date of the latest release
        """
        latest_version = package_info.get("latest_version")
        if latest_version is None:
            return None
        _, release_date = latest_version
        return release_date
