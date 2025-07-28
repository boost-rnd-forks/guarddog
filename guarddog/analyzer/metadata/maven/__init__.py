# Maven-specific metadata security rules
# Currently empty - rules can be added here in the future

from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.maven.unclaimed_maintainer_email_domain import (
    MavenUnclaimedMaintainerEmailDomainDetector,
)

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenUnclaimedMaintainerEmailDomainDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
