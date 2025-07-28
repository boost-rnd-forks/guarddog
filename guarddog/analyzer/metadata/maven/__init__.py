# Maven-specific metadata security rules

from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.maven.release_zero import MavenReleaseZeroDetector

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenReleaseZeroDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
