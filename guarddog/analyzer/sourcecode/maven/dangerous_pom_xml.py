from typing import Optional
import os
import subprocess
import xml.etree.ElementTree as ET
import re
import logging

from guarddog.analyzer.sourcecode.detector import Detector
from guarddog.utils.exceptions import PomXmlValidationError

OUTPUT_FILE = "effective-pom.xml"
NAMESPACE = {"mvn": "http://maven.apache.org/POM/4.0.0"}
DANGEROUS_PLUGINS = {
    "exec-maven-plugin",
    "maven-antrun-plugin",
    "groovy-maven-plugin",
    "jruby-maven-plugin",
    "jython-maven-plugin",
    "maven-site-plugin",
}
URL_PATHS = [
    ".//mvn:repository/mvn:url",
    ".//mvn:pluginRepository/mvn:url",
    ".//mvn:distributionManagement/mvn:repository/mvn:url",
    ".//mvn:distributionManagement/mvn:snapshotRepository/mvn:url",
]
SUSPICIOUS_TAGS = {"executable", "mainClass", "script", "argument", "arg", "argLine"}
EARLY_PHASES = {
    "validate",
    "initialize",
    "generate-sources",
    "process-resources",
    "compile",
    "generate-resources",
}
SAFE_CMD = ["git"]
TRUSTED_REPOS = [
    "repo.maven.apache.org",
    "repo.spring.io",
    "repo.eclipse.org",
    "repository.apache.org",
    "oss.sonatype.org",
    "repository.jboss.org",
    "maven.google.com",
    "maven.oracle.com",
    "packages.atlassian.com",
]

log = logging.getLogger("guarddog")


class MavenDangerousPomXML(Detector):
    def __init__(self):
        super().__init__(
            name="dangerous_pom_xml",
            description="Detects pom.xml files with dangerous configuration: unsafe protocol usage, "
            "dangerous plugins, code execution in lifecycle phases",
        )

    def detect(self, path: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
        Detects dangerous behaviours defined in the effective pom.xml of the java project in path
        """
        log.debug(f"Scanning for dangerous pom.xml in sourcecode: {path} ")
        if path is None:
            raise ValueError("path is needed to run heuristic " + self.get_name())
        message: str = ""
        result = False
        if not os.path.isdir(path):
            log.error(f"Error: '{path}' is not a directory - no pom.xml analysis.")
            return False, None
        effective_pom_path: str = self.get_effective_pom(path)
        if not effective_pom_path:
            return False, None
        message += f"\nAnalyzing the effective pom path generated at {effective_pom_path} from {path}.\n"
        http_unsafe, http_urls = self.http_unsafe(effective_pom_path)
        if http_unsafe:
            message += "\nUnsafe http usage detected:\n"
            for url in http_urls:
                message += f"\t- {url}\n"
            result = True

        untrusted_plugin_source, untrusted_urls = self.untrusted_download_source(
            effective_pom_path
        )
        if untrusted_plugin_source:
            message += "\nPlugin(s) downloaded from untrusted source(s): \n"
            for bad_url in untrusted_urls:
                message += f"\t - {bad_url}\n"
            result = True

        malicious_plugin_found, malicious_plugins_list = self.is_malicious_plugin(
            effective_pom_path
        )
        if malicious_plugin_found:
            message += "\nSuspicious plugins affecting lifecycle phases found: \n"
            for plugin in set(malicious_plugins_list):
                message += f"\t - {plugin}\n"
            result = True

        suspicious_tags: dict = self.dangerous_tags_combinations(effective_pom_path)
        for plugin in suspicious_tags:
            message += f"\nSuspicious tags combination found in plugin {plugin}: \n"
            message += (
                f"\tFound in <execution> : {suspicious_tags[plugin]['tag']} "
                f"bound with early phase {suspicious_tags[plugin]['phase']}"
            )
            result = True

        urls_in_cmd: bool = self.url_as_cmd_argument(effective_pom_path)
        if urls_in_cmd:
            message += "\n\nA URL was found to be used as a command argument in <argument> or <script>."
            result = True

        suspicious_argline, suspicious_commands = self.suspicious_argline_usage(
            effective_pom_path
        )
        if suspicious_argline:
            message += "\nA suspicious usage of <argLine> was detected in the effective pom: \n"
            for cmd in suspicious_commands:
                message += f"\t- <argLine>{cmd}"
            result = True

        return result, message

    def get_effective_pom(self, path: str) -> str:
        """
        Get the effective pom.xml file of the project in path.
        The pom.xml is supposed to be in the root directory: {path}/pom.xml
        Stores the resulting effective xml in OUTPUT_FILE
        """
        if not os.path.isdir(path) or not os.path.abspath(path).startswith(os.getcwd()):
            raise ValueError(f"Invalid path provided: {path}")

        pom_path = os.path.join(path, "pom.xml")

        if not os.path.isfile(pom_path):
            raise FileNotFoundError(f"Error: No 'pom.xml' found in '{path}'.")
        log.debug(f"pom.xml found at {path}/ ")

        command = ["mvn", "help:effective-pom", f"-Doutput={OUTPUT_FILE}"]
        effective_pom_path = os.path.join(path, OUTPUT_FILE)

        try:
            # create the effective pom xml
            subprocess.run(
                command, cwd=path, check=True, capture_output=True, text=True
            )
            if os.path.exists(effective_pom_path):
                log.debug(
                    f"Effective POM generated at: {os.path.abspath(effective_pom_path)}\n"
                )
            else:
                # This case is unlikely if `check=True` is used, but serves as a fallback.
                raise PomXmlValidationError(
                    f"Error: The effective pom file could not be created from {pom_path}."
                )
            return effective_pom_path

        except subprocess.CalledProcessError as e:
            raise PomXmlValidationError(
                f"Error: invalid pom.xml found at {pom_path}: {e}"
            )
        except Exception as e:
            raise PomXmlValidationError(
                f"Unexpected error during the effective pom generation from {pom_path}: {e}"
            )

    def http_unsafe(self, pom_path: str) -> tuple[bool, list]:
        """
        Detects unsafe http protocol in the effective pom.xml to get a custom plugin
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        bad_urls = []
        log.debug("\nScanning for insecure HTTP URLs...\n")
        found = False
        for path in URL_PATHS:
            for elem in root.findall(path, NAMESPACE):
                url = self.get_text(elem)
                if url.startswith("http://"):
                    log.debug(
                        f"Insecure URL found: {url} in the effective pom.xml {pom_path}."
                    )
                    found = True
                    bad_urls.append(url)
        return found, bad_urls

    def untrusted_download_source(self, pom_path: str) -> tuple[bool, list[str]]:
        """
        Detects when a custom plugin in <repository> or <pluginRepository>
        is not downloaded from a whitelisted trusted source.

        Returns a boolean and a list of detected not conform urls
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        log.debug("Scanning for untrusted plugins downloads...\n")
        found = False
        bad_urls = []
        download_urls = [".//mvn:repository/mvn:url", ".//mvn:pluginRepository/mvn:url"]
        for path in download_urls:
            for elem in root.findall(path, NAMESPACE):
                url = self.get_text(elem).split("//")[1]
                log.debug(f"analysing url {url}")
                if not any(
                    url.startswith(trusted_repo) for trusted_repo in TRUSTED_REPOS
                ):
                    found = True
                    bad_urls.append(url)
                    log.debug(f"Untrusted plugin source {url}.")
        return found, bad_urls

    def get_text(self, elem):
        return elem.text.strip() if elem is not None and elem.text else ""

    def is_malicious_plugin(self, pom_path: str) -> tuple[bool, list]:
        """
        Detects suspicious plugins in effective pom.xml
        using an exhaustive list of plugins in Java
        able to execute code in early lifecycle phases
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        log.debug("Scanning for dangerous plugins ...\n")
        results = []
        suspicious_plugin_found = False
        # detect dangerous plugins
        for plugin in root.findall(".//mvn:plugin", NAMESPACE):
            artifact_id = plugin.find("mvn:artifactId", NAMESPACE)
            plugin_id = self.get_text(artifact_id)
            if plugin_id in DANGEROUS_PLUGINS:
                # detects early phase specifications
                for phase in plugin.findall(".//mvn:phase", NAMESPACE):
                    phase_txt = self.get_text(phase)
                    if phase_txt in EARLY_PHASES:
                        suspicious_plugin_found = True
                        results.append(plugin_id)
                        log.debug(
                            f'Suspicious plugin found: "{plugin_id}" bound to early phase "{phase_txt}".'
                        )
                # detects suspicious tags usage by the detected plugin
                for tag in SUSPICIOUS_TAGS:
                    tag_elem = plugin.findall(f".//mvn:{tag}", NAMESPACE)
                    for t in tag_elem:
                        suspicious_plugin_found = True
                        results.append(plugin_id)
                        log.debug(
                            f'Suspicious plugin found: "{plugin_id}" using  suspicious tag <{tag}> {self.get_text(t)}'
                        )

        return suspicious_plugin_found, results

    def dangerous_tags_combinations(self, pom_path: str) -> dict:
        """
        Detects suspicious tags combinations in the effective pom.xml :
        If are found in an <execution> tag
            - an early lifecycle phase tag ("validate", "initialize", "generate-sources",
                "process-resources", "compile")
            - and a suspicious tag ("executable", "mainClass", "script", "argument")

            Return:
                dict(plugin_id: {phases: list, tags: (tag, cmd)})
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        results: dict = {}
        log.debug("\nScanning for dangerous tags ...\n")
        for plugin in root.findall(".//mvn:plugin", NAMESPACE):
            artifact_id = plugin.find("mvn:artifactId", NAMESPACE)
            plugin_id = self.get_text(artifact_id) or "(unknown-plugin)"

            early_phases = []
            tags_found = []
            for execution in plugin.findall(".//mvn:execution", NAMESPACE):
                phase = False
                has_susp_tag = False
                #  <execution> blocks bound to early phase
                phase_elem = execution.find("mvn:phase", NAMESPACE)
                phase_txt = self.get_text(phase_elem).lower()
                if phase_txt in EARLY_PHASES:
                    early_phases.append(phase_txt)
                    phase = True
                #  <execution> blocks with suspicious tags
                for tag in SUSPICIOUS_TAGS:
                    tag_elem = execution.find(f".//mvn:{tag}", NAMESPACE)
                    tag_txt = self.get_text(tag_elem)
                    if tag_txt and tag_txt not in SAFE_CMD:
                        has_susp_tag = True
                        tags_found.append((f"<{tag}>", tag_txt))
                # if both found
                if has_susp_tag and phase:
                    if plugin_id not in results:
                        results[plugin_id] = []
                    results[plugin_id].append(
                        {"phase": early_phases, "tag": tags_found}
                    )
                    log.debug(
                        f"Suspicious tags combination found in {plugin_id}: {tags_found} in phases {early_phases}"
                    )

        return results

    def url_as_cmd_argument(self, pom_path: str) -> bool:
        """
        Detects urls in <arguments> or <script> tags
        Having urls as command arguments is often related to a connection to a C2 server
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        found = False
        urls = ["http://", "https://", "ftp://"]
        log.debug("\nScanning for urls as cmd args ...\n")
        argument = root.findall(".//mvn:argument", NAMESPACE)
        script = root.findall(".//mvn:script", NAMESPACE)
        for elem in argument + script:
            arg = self.get_text(elem)
            for url in urls:
                if url in arg:
                    found = True
        return found

    def suspicious_argline_usage(self, pom_path: str) -> tuple[bool, list[str]]:
        """
        Detects suspicious argument in <argLine> tags
        - usage of -javaagent: , able to manipulate bytecode at runtime
            combined with
            - urls (http(s), ftp)
            - .jar files
        or
        - dynamic parameters: ${...}
        - suspicious commands (curl, wget, sh...)
        Returns
            - Bool: if suspicious command found in <argLine>
            - list | None: list of suspicious commands found
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        suspicious = False
        suspicious_commands = []
        log.debug("\nScanning for <argLine> commands ...\n")
        argLine = root.findall(".//mvn:argLine", NAMESPACE)
        for elem in argLine:
            cmd = self.get_text(elem)
            if "-javaagent:" in cmd:
                if re.search(r"(https?|ftp):\/\/", cmd) or re.search(r"\.jar", cmd):
                    suspicious = True
                    suspicious_commands.append(cmd)
                    log.warning("Suspicious url or .jar with -javaagent: in <argLine>")
            elif re.search(r"\${.*}", cmd):
                suspicious = True
                suspicious_commands.append(cmd)
                log.debug("Suspicious dynamic parameter ${...} in <argLine>")
            elif re.search(
                r"(bash|sh|nc|curl|wget|powershell|start|exec|eval|sys|scp|rsync|ncat|telnet|socat)",
                cmd,
            ):
                suspicious = True
                suspicious_commands.append(cmd)
                log.debug("Suspicious command in <argLine> (curl, wget, sh...)")
        return suspicious, suspicious_commands
