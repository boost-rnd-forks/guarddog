# Maven-specific metadata security rules
from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.maven.bundled_binary import MavenBundledBinary
from guarddog.analyzer.metadata.maven.deceptive_author import MavenDeceptiveAuthor
from guarddog.analyzer.metadata.maven.release_zero import MavenReleaseZeroDetector
from guarddog.analyzer.metadata.maven.unclaimed_maintainer_email_domain import (
    MavenUnclaimedMaintainerEmailDomainDetector,
)

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenBundledBinary,
    MavenDeceptiveAuthor,
    MavenReleaseZeroDetector,
    MavenUnclaimedMaintainerEmailDomainDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
