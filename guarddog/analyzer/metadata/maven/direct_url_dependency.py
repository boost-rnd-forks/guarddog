""" Direct URL Dependency Detector for Maven

Detects if a Maven package depends on direct URL dependencies
"""
import logging
import os
import xml.etree.ElementTree as ET
from typing import Optional
import re
from urllib.parse import urlparse

from guarddog.analyzer.metadata.detector import Detector

log = logging.getLogger("guarddog")

# Patterns for detecting direct URL dependencies in Maven
github_project_pattern = re.compile(r"^([\w\-\.]+)/([\w\-\.]+)")
git_url_pattern = re.compile(r"\.git$|^git://|^https?://.*\.git")


class MavenDirectURLDependencyDetector(Detector):
    """This heuristic detects Maven packages with direct URL dependencies.
    Dependencies fetched this way are not immutable and can be used to inject untrusted code
    or reduce the likelihood of a reproducible install.
    
    Maven specific patterns detected:
    - System scope dependencies with systemPath pointing to URLs
    - Repository URLs that are not standard Maven repositories
    - Dependencies with custom repository configurations
    """

    def __init__(self):
        super().__init__(
            name="direct_url_dependency",
            description="Identify Maven packages with direct URL dependencies. \
Dependencies fetched this way are not immutable and can be used to \
inject untrusted code or reduce the likelihood of a reproducible install.",
        )

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Detect direct URL dependencies in Maven packages by analyzing the pom.xml file.
        
        Args:
            package_info: Maven package metadata containing path information
            path: Optional path to the package
            name: Optional package name
            version: Optional package version
            
        Returns:
            tuple[bool, str]: (True if direct URLs found, message with details)
        """
        findings = []
        
        # Get pom.xml path from package_info
        pom_path = self._get_pom_path(package_info, path)
        if not pom_path or not os.path.exists(pom_path):
            log.debug(f"No pom.xml found for Maven package analysis")
            return False, "No pom.xml file found for analysis"
        
        log.debug(f"Analyzing pom.xml at: {pom_path}")
        
        try:
            # Parse the pom.xml file
            tree = ET.parse(pom_path)
            root = tree.getroot()
            
            # Detect namespace if present
            namespace = ""
            if "}" in root.tag:
                namespace = root.tag.split("}")[0].strip("{")
            ns = {"mvn": namespace} if namespace else {}
            
            # Check for system scope dependencies with direct URLs
            findings.extend(self._check_system_scope_dependencies(root, ns))
            
            # Check for custom repositories with direct URLs
            findings.extend(self._check_custom_repositories(root, ns))
            
            # Check for dependencies with version ranges pointing to Git
            findings.extend(self._check_git_dependencies(root, ns))
            
        except ET.ParseError as e:
            log.warning(f"Failed to parse pom.xml: {e}")
            return False, f"Failed to parse pom.xml: {e}"
        except Exception as e:
            log.error(f"Error analyzing pom.xml: {e}")
            return False, f"Error analyzing pom.xml: {e}"
        
        return len(findings) > 0, "\n".join(findings)
    
    def _get_pom_path(self, package_info, path: Optional[str]) -> Optional[str]:
        """Extract pom.xml path from package_info or construct from path."""
        # Try to get from package_info first
        if package_info and "path" in package_info:
            pom_path = package_info["path"].get("pom_path")
            if pom_path and os.path.exists(pom_path):
                return pom_path
        
        # Fallback to constructing from path
        if path:
            pom_path = os.path.join(path, "pom.xml")
            if os.path.exists(pom_path):
                return pom_path
        
        return None
    
    def _check_system_scope_dependencies(self, root, ns) -> list[str]:
        """Check for system scope dependencies with systemPath pointing to URLs."""
        findings = []
        
        # Find all dependencies with system scope
        dependencies = root.findall(".//mvn:dependency", ns)
        for dep in dependencies:
            scope = dep.find("mvn:scope", ns)
            system_path = dep.find("mvn:systemPath", ns)
            
            if (scope is not None and scope.text == "system" and 
                system_path is not None and system_path.text):
                
                system_path_value = system_path.text.strip()
                
                # Check if systemPath looks like a URL
                if self._is_url_like(system_path_value):
                    group_id = self._get_element_text(dep, "mvn:groupId", ns)
                    artifact_id = self._get_element_text(dep, "mvn:artifactId", ns)
                    findings.append(
                        f"System scope dependency {group_id}:{artifact_id} "
                        f"refers to direct URL: {system_path_value}"
                    )
        
        return findings
    
    def _check_custom_repositories(self, root, ns) -> list[str]:
        """Check for repository URLs that are suspicious or direct file URLs."""
        findings = []
        
        # Standard Maven repositories (trusted)
        trusted_repos = {
            "repo1.maven.org",
            "search.maven.org", 
            "central.maven.org",
            "repo.maven.apache.org",
            "oss.sonatype.org"
        }
        
        # Find all repository definitions
        repositories = root.findall(".//mvn:repository", ns)
        for repo in repositories:
            url_elem = repo.find("mvn:url", ns)
            repo_id = self._get_element_text(repo, "mvn:id", ns)
            
            if url_elem is not None and url_elem.text:
                repo_url = url_elem.text.strip()
                parsed_url = urlparse(repo_url)
                
                # Check for suspicious patterns
                if parsed_url.scheme in ["file", "ftp"]:
                    findings.append(
                        f"Repository '{repo_id}' uses direct file/FTP URL: {repo_url}"
                    )
                elif parsed_url.scheme in ["http", "https"]:
                    hostname = parsed_url.hostname
                    if hostname and hostname not in trusted_repos:
                        # Check for GitHub raw URLs or similar direct file hosting
                        if any(pattern in repo_url.lower() for pattern in 
                               ["raw.githubusercontent.com", "github.com/.*/.*/raw/", 
                                "bitbucket.org/.*/.*/raw/", "gitlab.com/.*/-/raw/"]):
                            findings.append(
                                f"Repository '{repo_id}' refers to direct file hosting URL: {repo_url}"
                            )
                        elif git_url_pattern.search(repo_url):
                            findings.append(
                                f"Repository '{repo_id}' refers to direct Git repository URL: {repo_url}"
                            )
        
        return findings
    
    def _check_git_dependencies(self, root, ns) -> list[str]:
        """Check for dependencies that might be pointing to Git repositories."""
        findings = []
        
        # Look for dependencies with unusual version patterns that might indicate Git refs
        dependencies = root.findall(".//mvn:dependency", ns)
        for dep in dependencies:
            version = self._get_element_text(dep, "mvn:version", ns)
            group_id = self._get_element_text(dep, "mvn:groupId", ns)
            artifact_id = self._get_element_text(dep, "mvn:artifactId", ns)
            
            if version:
                # Check for Git-like version patterns (commit hashes, branch names)
                if (len(version) == 40 and all(c in '0123456789abcdef' for c in version.lower()) or
                    version.startswith("${") or  # Property-based versions can be suspicious
                    any(keyword in version.lower() for keyword in ["master", "main", "HEAD", "trunk"])):
                    
                    findings.append(
                        f"Dependency {group_id}:{artifact_id} has suspicious version "
                        f"that may indicate direct Git reference: {version}"
                    )
        
        return findings
    
    def _is_url_like(self, path: str) -> bool:
        """Check if a path looks like a URL."""
        parsed = urlparse(path)
        return parsed.scheme in ["http", "https", "ftp", "file", "git"]
    
    def _get_element_text(self, parent, tag, ns) -> str:
        """Safely get text content from an XML element."""
        elem = parent.find(tag, ns)
        return elem.text.strip() if elem is not None and elem.text else "" 