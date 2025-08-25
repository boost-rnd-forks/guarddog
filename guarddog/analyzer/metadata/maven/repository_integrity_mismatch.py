"""Repository Integrity Mismatch Detector for Maven

Detects if a Maven package contains files that differ from the source repository
"""

import hashlib
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Optional, Tuple
import requests
from urllib.parse import urlparse

import pygit2  # type: ignore
import urllib3.util

from guarddog.analyzer.metadata.repository_integrity_mismatch import IntegrityMismatch
from guarddog.utils.archives import extract_jar

GH_REPO_REGEX = r"(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/)(?:[\w-]+)"
GH_REPO_OWNER_REGEX = r"(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)"
SCM_GIT_REGEX = (
    r"scm:git:(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)(?:\.git)?"
)
MAVEN_CENTRAL_BASE_URL = "https://repo1.maven.org/maven2"
TRUSTED_DOMAINS = {"repo1.maven.org", "search.maven.org"}

log = logging.getLogger("guarddog")


def download_packages_sources(
    dest_dir: str, group_id: str, artifact_id: str, version: str
) -> str:
    """
    Get the package sources jar from Maven Central
    Returns:
        - path to the downloaded .jar of sources files
    """
    log.debug("Downloading sources...")
    group_path = group_id.replace(".", "/")
    base_url = f"{MAVEN_CENTRAL_BASE_URL}/{group_path}/{artifact_id}/{version}"
    jar_sources_url = f"{base_url}/{artifact_id}-{version}-sources.jar"
    os.makedirs(dest_dir, exist_ok=True)
    jar_sources_path = os.path.join(dest_dir, f"{artifact_id}-{version}-sources.jar")
    try:
        r = requests.get(jar_sources_url, stream=True, timeout=10, verify=True)
        final_url = r.url
        parsed = urlparse(final_url)
        if parsed.hostname not in TRUSTED_DOMAINS:
            raise ValueError(
                f"Unsafe redirect detected: {final_url} not in trusted domains"
            )

        if r.status_code != 200:
            raise Exception(
                f"Failed to download Maven package from {jar_sources_url} (status {r.status_code})"
            )

        with open(jar_sources_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        log.debug("successfully retrieved sources!")
    except Exception as e:
        raise Exception(f"Error retrieving Maven package sources: {e}")

    log.debug(f"Downloaded JAR sources to: {jar_sources_path}")
    return jar_sources_path


def extract_owner_and_repo(url) -> Tuple[Optional[str], Optional[str]]:
    """Extract GitHub owner and repository from URL"""
    match = re.search(GH_REPO_OWNER_REGEX, url)
    if match:
        owner = match.group(1)
        repo = match.group(2)
        log.debug(f"owner: {owner}, repo: {repo}")
        return owner, repo
    return None, None


def find_best_github_candidate(all_candidates_and_highlighted_link, name):
    """
    This method goes through multiple URLs and checks which one is the most suitable to be used as GitHub URL for
    the project repository.
    If the repository homepage is a GitHub URL, it is used in priority
    """
    candidates, best_github_candidate = all_candidates_and_highlighted_link

    # if the project url is a GitHub repository, we should follow this as an instruction. Users will click on it
    if best_github_candidate is not None:
        best_github_candidate = best_github_candidate.replace("http://", "https://")
        url = urllib3.util.parse_url(best_github_candidate)
        if url.host == "github.com":
            return best_github_candidate
    clean_candidates = []
    for entry in candidates:
        # let's do some cleanup
        url = urllib3.util.parse_url(entry)
        if url.host != "github.com":
            continue
        if url.scheme == "http":
            entry = entry.replace("http://", "https://")
        clean_candidates.append(entry)
    for entry in clean_candidates:
        if f"/{name.lower()}" in entry.lower():
            return entry
    # solution 1 did not work, let's be a bit more aggressive
    for entry in clean_candidates:
        owner, repo = extract_owner_and_repo(entry)
        if repo is not None and (
            # Similar name matching logic as PyPI version
            repo.lower() in name.lower()
            or name.lower() in repo.lower()
        ):
            return entry
    return None


def get_file_hash(path):
    """Calculate SHA256 hash of a file"""
    with open(path, "rb") as f:
        # Read the contents of the file
        file_contents = f.read()
        # Create a hash object
        hash_object = hashlib.sha256()
        # Feed the file contents to the hash object
        hash_object.update(file_contents)
        # Get the hexadecimal hash value
        return hash_object.hexdigest(), str(file_contents).strip().splitlines()


def _ensure_proper_url(url):
    """Ensure URL has proper protocol"""
    parsed = urllib3.util.parse_url(url)
    if parsed.scheme is None:
        url = f"https://{url}"
    return url


def find_github_candidates_from_pom(pom_path) -> Tuple[set[str], Optional[str]]:
    """Extract GitHub URLs from Maven POM file"""
    if not os.path.isfile(pom_path):
        log.warning(f"POM file {pom_path} does not exist.")
        return set(), None

    github_urls = set()
    best_candidate = None

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # Detect namespace if present
        namespace = ""
        if "}" in root.tag:
            namespace = root.tag.split("}")[0].strip("{")
        ns = {"mvn": namespace} if namespace else {}

        # Look for SCM section
        scm = root.find(".//mvn:scm", ns) if ns else root.find(".//scm")
        if scm is not None:
            # Check connection URLs
            connection = (
                scm.find("mvn:connection", ns) if ns else scm.find("connection")
            )
            dev_connection = (
                scm.find("mvn:developerConnection", ns)
                if ns
                else scm.find("developerConnection")
            )
            scm_url = scm.find("mvn:url", ns) if ns else scm.find("url")

            # Parse SCM URLs
            for element in [connection, dev_connection, scm_url]:
                if element is not None and element.text:
                    url_text = element.text.strip()

                    # Handle SCM-format URLs (scm:git:https://github.com/...)
                    scm_match = re.search(SCM_GIT_REGEX, url_text)
                    if scm_match:
                        github_url = f"https://github.com/{scm_match.group(1)}/{scm_match.group(2)}"
                        github_urls.add(_ensure_proper_url(github_url))
                        if best_candidate is None:
                            best_candidate = github_url
                    else:
                        # Handle regular GitHub URLs
                        gh_match = re.search(GH_REPO_REGEX, url_text)
                        if gh_match:
                            github_urls.add(_ensure_proper_url(url_text))
                            if best_candidate is None:
                                best_candidate = url_text

        # Also look for GitHub URLs in other common places
        url_element = root.find(".//mvn:url", ns) if ns else root.find(".//url")
        if url_element is not None and url_element.text:
            url_text = url_element.text.strip()
            if "github.com" in url_text:
                github_urls.add(_ensure_proper_url(url_text))
                if best_candidate is None:
                    best_candidate = url_text

    except ET.ParseError as e:
        log.warning(f"Failed to parse POM: {pom_path}, error: {e}")
    except Exception as e:
        log.warning(f"Unexpected error parsing POM: {e}")

    return github_urls, best_candidate


# Maven-specific excluded extensions and patterns
EXCLUDED_EXTENSIONS = [".md", ".txt", ".rst", "mf", ".properties"]
EXCLUDED_PATTERNS = ["META-INF/versions"]


def exclude_result(file_name: str) -> bool:
    """
    This method filters out some results that are known false positives for Maven:
    * if the file is a documentation file (based on its extension)
    * if the file is in version directory
    """
    if not file_name:
        return False

    for extension in EXCLUDED_EXTENSIONS:
        if file_name.lower().endswith(extension):
            return True

    for pattern in EXCLUDED_PATTERNS:
        if file_name.lower().startswith(pattern.lower()):
            return True

    return False


def find_non_java_files_mismatches(
    decompressed_path: str, sources_path: str
) -> list[dict]:
    """
    Find the files that differ between the two provided java repositories:
    The decompressed built jar and the corresponding java sources from Maven.

    Analyses non java files only: computes hash of each file

    If a file is present in the decompressed_path but is not present in the
    public `source_path`: it is considered dangerous!

    The opposite is ignored: if a file in the public `sources_path` is missing in
    the build package `decompressed_path`, it is considered fine.

    Args:
        - `decompressed_path` (str): path of the sketchy project. Should not have additional files
        - `sources_path` (str): trusted path, reference

    Returns:
        mismatchs (list[dict]):
            - "decompressed_built_file": decompressed_file_path,
            - "source_file" source_file_path
    """
    if not decompressed_path or not os.path.isdir(decompressed_path):
        raise FileExistsError(
            f"Invalid project path provided {decompressed_path}. No repo comparison."
        )
    if not sources_path or not os.path.isdir(sources_path):
        raise FileExistsError(
            f"Invalid project path provided {sources_path}. No repo comparison."
        )

    log.debug("Looking for non java files mismatches...")
    mismatch = []
    for decompressed_root, dir, decompressed_files in os.walk(decompressed_path):
        decompressed_rel_path = os.path.relpath(decompressed_root, decompressed_path)
        sources_root = os.path.join(sources_path, decompressed_rel_path)

        if not os.path.exists(sources_root):
            if exclude_result(decompressed_rel_path):
                continue
            log.warning(
                f"File {decompressed_rel_path} does not exist in sources, additional files in built package!"
            )
            # additional files in the built package!!
            res = {
                "decompressed_built_file": os.path.join(
                    decompressed_root, decompressed_rel_path
                ),
                "source_file": "None",
            }
            mismatch.append(res)
            continue

        # get the files in the respective dir in sources
        source_files = list(
            filter(
                lambda x: os.path.isfile(os.path.join(sources_root, x)),
                os.listdir(sources_root),
            )
        )

        for decompressed_f in decompressed_files:
            if decompressed_f.endswith(".class"):
                # do not compare hashes of sources .java with compiled .class!
                continue

            if exclude_result(decompressed_f):
                continue

            if decompressed_f not in source_files:
                # if decompressed project has additional files not present in the public sources-> dangerous !
                # danger || add mismatch
                log.warning(
                    f"The file {decompressed_f} is in the built project but not in the public sources!"
                )
                res = {
                    "decompressed_built_file": os.path.join(
                        decompressed_rel_path, decompressed_f
                    ),
                    "source_file": "None",
                }
                mismatch.append(res)
                continue

            decompressed_hash, d_content = get_file_hash(
                os.path.join(decompressed_root, decompressed_f)
            )
            source_hash, s_content = get_file_hash(
                os.path.join(sources_root, decompressed_f)
            )

            if decompressed_hash != source_hash:
                res = {
                    "decompressed_built_file": os.path.join(
                        decompressed_rel_path, decompressed_f
                    ),
                    "source_file": os.path.join(sources_root, decompressed_f),
                }
                mismatch.append(res)

    return mismatch


def find_java_files_mismatch(decompressed_path: str, sources_path: str) -> list[dict]:
    """
    Analyses the decompressed built jar `decompressed_path` and the corresponding java sources `sources_path` to find incoherences regarding java files (.java and .class).

    (Since it is not possible to compare .class hashes with the corresponding .java file, we only verify the files names and location.)

    Returns:
        mismatchs (list[dict]):
            - "file": mismatch_decompressed_file_path,
            - "decompressed_sha256" decompressed_file_hash (sha256)
            - "maven_sources_sha256": source_file_hash (sha256)
    """


def find_suitable_tags_in_list(tags, version):
    """Find tags that match the given version"""
    tag_candidates = []
    for tag_name in tags:
        normalized_tag = tag_name.lstrip("refs/tags/").lstrip("v").lstrip("release-")
        if normalized_tag and normalized_tag in version:
            tag_candidates.append(tag_name)
    return tag_candidates


def find_suitable_tags(repo, version):
    """Find suitable Git tags for the given version"""
    tags_regex = re.compile(r"^refs/tags/(.*)")
    tags = []
    for ref in repo.references:
        match = tags_regex.match(ref)
        if match is not None:
            tags.append(match.group(0))

    return find_suitable_tags_in_list(tags, version)


class MavenIntegrityMismatchDetector(IntegrityMismatch):
    """
    This heuristic compares source code available on the Maven package source code repository (e.g. GitHub),
    and source code published on Maven Central. If a file is on both sides but has a different content,
    this heuristic will flag the package.

    This helps identify packages whose release artifacts were modified directly on Maven Central.

    Current gaps:
    * Does not check for extraneous files in the release artifacts
    * Does not run in parallel, so can be slow for large code bases
    * Only compares decompressed JAR contents, not decompiled Java source
    """

    RULE_NAME = "repository_integrity_mismatch"

    def __init__(self):
        super().__init__()

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        if name is None:
            raise Exception("Detector needs the name of the package")
        if path is None:
            raise Exception("Detector needs the path of the package")

        log.debug(
            f"Running repository integrity mismatch heuristic on Maven package {name} version {version}"
        )
        if version is None:
            version = package_info.get("info", {}).get("version")
        if version is None:
            raise Exception("Could not find suitable version to scan")

        tmp_dir = os.path.dirname(path)
        if tmp_dir is None:
            raise Exception("no current scanning directory")

        group_id, artifact_id = name.split(":")
        jar_sources_path: str = download_packages_sources(
            tmp_dir, group_id, artifact_id, version
        )
        if not jar_sources_path or not os.path.exists(jar_sources_path):
            return False, "Could not find the package sources"

        sources_path = os.path.join(tmp_dir, "sources")
        extract_jar(jar_sources_path, sources_path)
        if not sources_path or not os.path.isdir(sources_path):
            return False, "Could not decompress the package sources"

        decompressed_path = package_info.get("path", {}).get("decompressed_path")
        if not decompressed_path or not os.path.exists(decompressed_path):
            return False, "Could not find decompressed package contents"

        log.debug("Looking for mismatches...")

        non_java_mismatch: list[dict] = find_non_java_files_mismatches(
            decompressed_path, sources_path
        )
        message = "\n".join(
            map(
                lambda x: "\t* "
                + "Decompressed built Maven package: "
                + x["decompressed_built_file"]
                + " and "
                + "decompressed Maven corresponding sources: "
                + x["source_file"],
                non_java_mismatch,
            )
        )
        return (
            len(non_java_mismatch) > 0,
            f"Some files present in the package are different from the ones in the corresponding Maven sources for "
            f"the same version of the package: \n{message}",
        )
