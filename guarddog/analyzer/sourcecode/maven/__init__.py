# Maven-specific metadata security rules
# Currently empty - rules can be added here in the future
from guarddog.analyzer.sourcecode.maven.dangerous_pom_xml import MavenDangerousPomXML
from guarddog.analyzer.sourcecode.detector import Detector

MAVEN_PYTHON_RULES: dict[str, Detector] = {}

classes = [
    MavenDangerousPomXML,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_PYTHON_RULES[detectorInstance.get_name()] = detectorInstance
