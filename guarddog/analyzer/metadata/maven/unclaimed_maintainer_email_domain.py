from guarddog.analyzer.metadata.unclaimed_maintainer_email_domain import (
    UnclaimedMaintainerEmailDomainDetector,
)


class MavenUnclaimedMaintainerEmailDomainDetector(
    UnclaimedMaintainerEmailDomainDetector
):
    def __init__(self):
        super().__init__("maven")

    def get_email_addresses(self, package_info: dict) -> set[str]:
        return set(package_info["info"]["email"])
