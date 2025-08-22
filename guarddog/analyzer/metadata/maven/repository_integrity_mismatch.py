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

GH_REPO_REGEX = r"(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/)(?:[\w-]+)"
GH_REPO_OWNER_REGEX = r"(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)"
SCM_GIT_REGEX = (
    r"scm:git:(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)(?:\.git)?"
)
MAVEN_CENTRAL_BASE_URL = "https://repo1.maven.org/maven2"
TRUSTED_DOMAINS = {"repo1.maven.org", "search.maven.org"}

log = logging.getLogger("guarddog")


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
EXCLUDED_EXTENSIONS = [".md", ".txt", ".rst", ".class", ".jar", ".war"]
EXCLUDED_PATTERNS = ["target/", ".*", "*.iml", "*.ipr", "*.iws"]


def exclude_result(file_name, repo_root, pkg_root):
    """
    This method filters out some results that are known false positives for Maven:
    * if the file is a documentation file (based on its extension)
    * if the file is a compiled artifact (.class, .jar, etc.)
    * if the file is in target directory or other build artifacts
    * if the file is IDE-specific configuration
    """
    for extension in EXCLUDED_EXTENSIONS:
        if file_name.endswith(extension):
            return True

    for pattern in EXCLUDED_PATTERNS:
        if pattern.startswith("*") and file_name.endswith(pattern[1:]):
            return True
        elif pattern == ".*" and file_name.startswith("."):
            return True
        elif file_name.startswith(pattern):
            return True

    # Maven-specific: exclude pom.xml differences if they are just formatting
    if file_name == "pom.xml":
        try:
            # Parse both POM files and compare their canonical form
            repo_tree = ET.parse(os.path.join(repo_root, file_name))
            pkg_tree = ET.parse(os.path.join(pkg_root, file_name))

            # Simple comparison - could be made more sophisticated
            repo_str = ET.tostring(repo_tree.getroot(), encoding="unicode")
            pkg_str = ET.tostring(pkg_tree.getroot(), encoding="unicode")

            # Normalize whitespace for comparison
            repo_normalized = " ".join(repo_str.split())
            pkg_normalized = " ".join(pkg_str.split())

            if repo_normalized == pkg_normalized:
                return True
        except Exception:
            # If parsing fails, continue with hash comparison
            pass

    return False


def find_mismatch_for_tag(repo, tag, base_path, repo_path):
    """Find mismatched files between repository tag and package"""
    log.debug(f"checkout {tag}")
    try:
        repo.checkout(tag)
        log.debug("checkout successful!!!")
    except Exception as e:
        # log.error(f"Error running `git checkout {tag}`: {e}")
        raise Exception(f"Error running `git checkout {tag}`: {e}")
    mismatch = []

    for root, dirs, files in os.walk(base_path):
        relative_path = os.path.relpath(root, base_path)
        repo_root = os.path.join(repo_path, relative_path)
        log.debug(f"repo root: {repo_root}")

        if not os.path.exists(repo_root):
            log.debug("Path does not exist")
            continue
        log.debug("analysing files...")

        repo_files = list(
            filter(
                lambda x: os.path.isfile(os.path.join(repo_root, x)),
                os.listdir(repo_root),
            )
        )

        for file_name in repo_files:
            if file_name not in files:  # ignore files we don't have in the distribution
                continue
            repo_hash, repo_content = get_file_hash(os.path.join(repo_root, file_name))
            pkg_hash, pkg_content = get_file_hash(os.path.join(root, file_name))

            if repo_hash != pkg_hash:
                if exclude_result(file_name, repo_root, root):
                    continue

                res = {
                    "file": os.path.join(relative_path, file_name),
                    "repo_sha256": repo_hash,
                    "pkg_sha256": pkg_hash,
                }
                mismatch.append(res)

    return mismatch


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

        # Extract POM path from package_info
        pom_path = package_info.get("path", {}).get("pom_path")
        if not pom_path or not os.path.exists(pom_path):
            return False, "Could not find POM file for the package"

        # Extract GitHub URLs from POM
        github_urls, best_github_candidate = find_github_candidates_from_pom(pom_path)
        log.debug(f"Found a github url: {github_urls}")
        if len(github_urls) == 0:
            return False, "Could not find any GitHub url in the project's POM"

        # Find the best GitHub URL
        github_url = find_best_github_candidate(
            (github_urls, best_github_candidate), name
        )
        if github_url is None:
            log.warning("Could not find a good GitHub url in the project's POM")
            return False, "Could not find a good GitHub url in the project's POM"

        log.debug(f"Using GitHub URL {github_url}")

        # Get version from package_info if not provided
        if version is None:
            version = package_info.get("info", {}).get("version")
        if version is None:
            raise Exception("Could not find suitable version to scan")

        tmp_dir = os.path.dirname(path)
        if tmp_dir is None:
            raise Exception("no current scanning directory")

        repo_path = os.path.join(tmp_dir, "sources", name)
        log.debug(f"Cloning the repo... into {repo_path}")
        try:
            repo = pygit2.clone_repository(url=github_url, path=repo_path)
            log.debug("Successfully cloned github repo")
            log.debug(os.listdir(repo_path))
        except pygit2.GitError as git_error:
            # Handle generic Git-related errors
            raise Exception(
                f"Error while cloning repository {str(git_error)} with github url {github_url}"
            )
        except Exception as e:
            # Catch any other unexpected exceptions
            raise Exception(
                f"An unexpected error occurred: {str(e)}.  github url {github_url}"
            )

        tag_candidates = find_suitable_tags(repo, version)
        if len(tag_candidates) == 0:
            return False, "Could not find any suitable tag in repository"
        log.debug(f"Tags : {tag_candidates}")
        target_tag = None
        # TODO: this one is a bit weak. let's find something stronger - maybe use the closest string?
        for tag in tag_candidates:
            target_tag = tag

        # Use decompressed path from Maven scanner
        base_path = package_info.get("path", {}).get("decompressed_path")
        if not base_path or not os.path.exists(base_path):
            return False, "Could not find decompressed package contents"
        log.debug(f"base path: {base_path}: {os.listdir(base_path)}")
        log.debug("look for mismatches")
        _, artifact_id = name.split(":")
        repo_path_final = os.path.join(repo_path, artifact_id, "src")
        mismatch = find_mismatch_for_tag(repo, target_tag, base_path, repo_path_final)
        message = "\n".join(map(lambda x: "* " + x["file"], mismatch))
        return (
            len(mismatch) > 0,
            f"Some files present in the package are different from the ones on GitHub for "
            f"the same version of the package: \n{message}",
        )
