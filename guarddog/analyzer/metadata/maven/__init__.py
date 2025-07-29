# Maven-specific metadata security rules
# Currently empty - rules can be added here in the future
from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.maven.empty_information import MavenEmptyInfoDetector

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenEmptyInfoDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
