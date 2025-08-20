# Maven-specific metadata security rules
from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.maven.empty_information import MavenEmptyInfoDetector
from guarddog.analyzer.metadata.maven.potentially_compromised_email_domain import (
    MavenPotentiallyCompromisedEmailDomainDetector,
)
from guarddog.analyzer.metadata.maven.bundled_binary import MavenBundledBinary
from guarddog.analyzer.metadata.maven.deceptive_author import MavenDeceptiveAuthor
from guarddog.analyzer.metadata.maven.file_type_mismatch import MavenFileTypeMismatchDetector
from guarddog.analyzer.metadata.maven.release_zero import MavenReleaseZeroDetector

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenEmptyInfoDetector,
    MavenPotentiallyCompromisedEmailDomainDetector,
    MavenBundledBinary,
    MavenDeceptiveAuthor,
    MavenFileTypeMismatchDetector,
    MavenReleaseZeroDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
