import logging
import os
import typing
import xml.etree.ElementTree as ET
import requests
import re
import filecmp
import shutil
from datetime import datetime, timezone
from urllib.parse import urlparse

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import decompile_jar, extract_jar, find_pom

log = logging.getLogger("guarddog")

MAVEN_CENTRAL_BASE_URL = "https://repo1.maven.org/maven2"
TRUSTED_DOMAINS = {"repo1.maven.org", "search.maven.org"}


class MavenPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.MAVEN))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> typing.Tuple[dict, str]:
        """
        Downloads the package from Maven Central (.jar)
        Downloads the corresponding pom file
        Decompressed the .jar
        Decompile the .jar
        Args:
            * `package_name` (str): group_id:artifact_id of the package on Maven
            * `version` (str): version of the package
            * `directory` (str): name of the dir to host the package. Created if does not exist
        Returns:
            * package_info (dict): necessary metadata for analysis
                - `path` (str): path to the local package:
                    - pom.xml
                    - decompressed/decompressed_jar
                    - decompiled/decompiled_java_files
            * path to the decompiled sourcecode
        """
        try:
            group_id, artifact_id = package_name.split(":")
        except ValueError:
            raise Exception(
                f"Invalid package format: '{package_name}'. Expected 'groupId:artifactId'"
            )
        if version is None:
            latest_version_info = self.get_latest_maven_version(group_id, artifact_id)
            if latest_version_info is None:
                raise ValueError(
                    "Version must be specified for Maven packages. Could not find latest version"
                )
            else:
                version, release_date = latest_version_info
                log.debug("No version specified")
                log.debug(
                    f"-->Using latest version {version} of {package_name} released on {release_date}."
                )

        if not directory:
            directory = artifact_id

        jar_path, pom_path = self.download_package(
            group_id, artifact_id, directory, version
        )

        # decompress jar
        decompressed_path: str = ""
        if jar_path.endswith(".jar"):
            decompressed_path = os.path.join(directory, "decompressed")
            extract_jar(jar_path, decompressed_path)
        else:
            log.error(f"Invalid JAR archive {jar_path}.")
        if not (
            os.path.exists(decompressed_path)
            and os.path.isdir(decompressed_path)
            and len(os.listdir(decompressed_path)) > 0
        ):
            log.error(f"The project could not be extracted from {jar_path}")

        # decompile jar
        decompiled_path: str = os.path.join(directory, "decompiled")
        decompile_jar(jar_path, decompiled_path)

        # diff between retrieved and decompressed pom
        jar_pom: tuple[bool, str] | None = self.diff_pom(
            decompressed_path, group_id, artifact_id, pom_path
        )
        if jar_pom:
            same, pom_jar_path = jar_pom
            if same:
                log.debug(
                    "The poms retrieved from Maven and from the decompressed project are the same!"
                )
            else:
                log.warning(
                    "The 2 found pom.xml for the project differ."
                    f"Using the pom found in the decompressed project: {pom_jar_path}"
                )
                pom_path = pom_jar_path
        # move pom file in decompiled project for source code analysis
        shutil.move(pom_path, decompiled_path)
        pom_path = os.path.join(decompiled_path, "pom.xml")

        # package_info
        package_info: dict = self.get_package_info(
            pom_path, decompressed_path, decompiled_path, group_id, artifact_id, version
        )
        log.debug(f"Package info: \n---\n{package_info}\n---")
        return package_info, decompiled_path

    def download_package(
        self, group_id: str, artifact_id: str, directory: str, version: str
    ) -> tuple[str, str]:
        """
        Downloads the Maven package .jar and pom for the specified version
        in directory
        Args:
            * `package_name` (str): group_id:artifact_id of the package on Maven
            * `version` (str): version of the package
            * `directory` (str): name of the dir to host the package. Created if does not exist
        Returns:
            Paths of the downloaded jar file and the corresponding downloaded pom.xml
        """

        group_path = group_id.replace(".", "/")

        # urls to download pom and jar
        base_url = f"{MAVEN_CENTRAL_BASE_URL}/{group_path}/{artifact_id}/{version}"
        jar_url = f"{base_url}/{artifact_id}-{version}.jar"
        pom_url = f"{base_url}/{artifact_id}-{version}.pom"

        # destination files
        log.debug(f"Downloading package in {directory} ")
        os.makedirs(directory, exist_ok=True)
        jar_path = os.path.join(directory, f"{artifact_id}-{version}.jar")
        pom_path = os.path.join(directory, "pom.xml")

        # We could also use the download_decompressed method from scanner.py
        try:
            for url, path in [(jar_url, jar_path), (pom_url, pom_path)]:
                # verify=True ensures SSL certificate validation
                r = requests.get(url, stream=True, timeout=10, verify=True)
                final_url = r.url
                parsed = urlparse(final_url)
                if parsed.hostname not in TRUSTED_DOMAINS:
                    raise ValueError(
                        f"Unsafe redirect detected: {final_url} not in trusted domains"
                    )

                if r.status_code != 200:
                    raise Exception(
                        f"Failed to download Maven package from {url} (status {r.status_code})"
                    )
                with open(path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

            log.debug(f"Downloaded JAR to: {jar_path}")
            log.debug(f"Downloaded POM to: {pom_path}")
            return jar_path, pom_path

        except Exception as e:
            raise Exception(f"Error retrieving Maven package: {e}")

    def find_pom(self, path: str, groupId: str, artifactId: str) -> str | None:
        """
        Finds the pom.xml in the package at `path` if exists
        """
        pom_dir = os.path.join(path, "META-INF", "maven", groupId, artifactId)
        if not os.path.isdir(pom_dir):
            log.warning(f"Directory {pom_dir} does not exist. Cannot look for pom.xml.")
            return None
        log.debug("Looking for pom.xml in the project...")
        pom_path = os.path.join(pom_dir, "pom.xml")
        if os.path.isfile(pom_path):
            log.debug("Found pom.xml in the decompressed project!")
            return pom_path
        else:
            log.warning(f"No pom.xml found at {pom_path}")
            return None

    def diff_pom(
        self, path: str, groupId: str, artifactId: str, pom_path: str
    ) -> tuple[bool, str] | None:
        """
        Args
            - `path` (str): path to the decompressed project
            - `groupId` (str): groupid of the package
            - `artifactId` (str): artifact id of the package
            - `pom_path` (str): pom.xml path to compare the project pom to

        Compare both poms and returns a bool
        Returns:
            - True if same poms
            - False if not
            - If pom found, returns the pom path
        """
        if not os.path.exists(pom_path):
            return None
        jar_pom = self.find_pom(path, groupId, artifactId)
        if not jar_pom:  # search recursively
            jar_pom = find_pom(path)
        if jar_pom:
            return filecmp.cmp(jar_pom, pom_path), jar_pom
        else:
            return None

    def get_latest_maven_version(self, group_id: str, artifact_id: str):
        """
        Fetches the latest release of the project and the release date
        from https://search.maven.org/solrsearch/select
        Returns
            - latest-version: str
            - release-date: datetime
        """
        url = "https://search.maven.org/solrsearch/select"
        params = {
            "q": f'g:"{group_id}" AND a:"{artifact_id}"',
            "rows": "1",
            "wt": "json",
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                docs = data.get("response", {}).get("docs", [])
                if docs:
                    latest_version = docs[0].get("latestVersion")
                    timestamp = docs[0].get("timestamp")
                    if latest_version and timestamp:
                        release_date = datetime.fromtimestamp(
                            timestamp / 1000, timezone.utc
                        )
                        log.debug(
                            f"Latest release date of {group_id}:{artifact_id}: {release_date}"
                        )
                        return latest_version, release_date
        except requests.exceptions.ConnectionError:
            log.error("Failed to connect to Maven repository.")
        except requests.exceptions.Timeout:
            log.error("Request to Maven repository timed out.")
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while fetching Maven data: {e}")
        log.error(f"No latest release found for {group_id}:{artifact_id}.")
        return None, None

    def normalize_email(self, email: str) -> str:
        """
        Normalize emails "name ([at]) domain.com"
        into emails "name@domain.com"
        """
        if "@" not in email:
            normalized_email = re.sub(
                r"\s*(\(|\[)?\s*at\s*(\)|\])?\s*", "@", email, flags=re.IGNORECASE
            )
        else:
            normalized_email = email
        return normalized_email.strip()

    def get_package_info(
        self,
        pom_path: str,
        decompressed_path: str,
        decompiled_path: str,
        group_id: str,
        artifact_id: str,
        version: str,
    ) -> dict:
        """
        Returns a dict with package info from args and retrieved from parsing pom.xml
        "info"
            - "groupid"
            - "artifactid"
            - "version"
            - "email": list[str]
        "path"
            - "pom_path"
            - "decompressed_path"
            - "decompiled_path"
        """
        emails = []
        description = ""
        log.debug("Parsing pom...")
        if not os.path.isfile(pom_path):
            log.error(f"WARNING: {pom_path} does not exist.")
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Detect namespace if present
            namespace = ""
            if "}" in root.tag:
                namespace = root.tag.split("}")[0].strip("{")
            else:
                namespace = "http://maven.apache.org/POM/4.0.0"
            ns = {"mvn": namespace} if namespace else {}

            # find email
            for dev in root.findall(".//mvn:developer", ns):
                email = dev.find("mvn:email", ns)
                if email is not None and email.text:
                    normalized_email: str = self.normalize_email(email.text.strip())
                    emails.append(normalized_email)
            if not emails:
                log.warning("No email found in the pom.")

            # find description
            # Find <description> element
            description_elem = root.find("mvn:description", ns)
            if description_elem is not None and description_elem.text:
                description = description_elem.text.strip()
                log.debug(f"<description> in pom: \n---\n{description}\n---")
            else:
                log.warning("No description found in pom")

        except ET.ParseError as e:
            log.error(f"Failed to parse POM: {pom_path}, error: {e}")
        except Exception as e:
            log.error(f"Unexpected error parsing POM: {e}")

        result = self.get_latest_maven_version(group_id, artifact_id)
        if result is not None:
            latest_release, date = result
        else:
            latest_release, date = "unknown", "unknown"

        return {
            "info": {
                "groupid": group_id,
                "artifactid": artifact_id,
                "version": version,
                "latest_version": (latest_release, date),
                "email": emails,
                "description": description,
            },
            "path": {
                "pom_path": pom_path,
                "decompressed_path": decompressed_path,
                "decompiled_path": decompiled_path,
            },
        }
