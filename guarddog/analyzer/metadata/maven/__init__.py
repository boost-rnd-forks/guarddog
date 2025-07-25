# Maven-specific metadata security rules

from guarddog.analyzer.metadata.maven.typosquatting import MavenTyposquatDetector
from guarddog.analyzer.metadata.detector import Detector


MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenTyposquatDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
