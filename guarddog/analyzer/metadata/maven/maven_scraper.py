#!/usr/bin/env python3

import json
import logging
import os
import re
import time
from typing import Optional, List, Dict
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MavenScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                           '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        })

    def url_encode(self, text: str) -> str:
        """
        Custom URL encoding for package names.
        
        This method replaces specific characters in the input string with their
        percent-encoded equivalents. It is a custom implementation and does not
        follow standard URL encoding conventions.
        
        Characters encoded:
            ':' -> '%3A'
            '/' -> '%2F'
            '@' -> '%40'
            ' ' -> '%20'
            '+' -> '%2B'
            '=' -> '%3D'
            '&' -> '%26'
            '?' -> '%3F'
            '#' -> '%23'
        
        Args:
            text (str): The input string to encode.
        
        Returns:
            str: The encoded string with specific characters replaced.
        """
        # Replace characters that need encoding in URLs
        replacements = {
            ':': '%3A',
            '/': '%2F',
            '@': '%40',
            ' ': '%20',
            '+': '%2B',
            '=': '%3D',
            '&': '%26',
            '?': '%3F',
            '#': '%23'
        }
        result = text
        for char, encoded in replacements.items():
            result = result.replace(char, encoded)
        return result

    def get_mvn_popular_page(self, page: int) -> List[str]:
        """Scrape popular Maven packages from mvnrepository.com page"""
        url = f"https://mvnrepository.com/popular?p={page}"

        try:
            response = self.session.get(url)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to get page {page}: {e}")
            return []

        html_content = response.text
        artifacts = set()

        # Find "Top Projects" section using regex
        top_projects_match = re.search(r'<h1[^>]*>Top Projects</h1>', html_content)
        if not top_projects_match:
            logger.warning(f"Could not find 'Top Projects' section on page {page}")
            return []

        # Extract content after "Top Projects" heading
        start_pos = top_projects_match.end()

        # Find the "Prev" link to know where to stop
        prev_match = re.search(r'<a[^>]*>Prev</a>', html_content[start_pos:])
        if prev_match:
            end_pos = start_pos + prev_match.start()
            section_content = html_content[start_pos:end_pos]
        else:
            # If no "Prev" found, take a reasonable chunk
            section_content = html_content[start_pos:start_pos + 10000]

        # Find all href attributes that start with "/artifact/" - matching Go logic exactly
        href_pattern = r'href=["\']?(/artifact/[^"\'>\s]+)["\']?'
        href_matches = re.findall(href_pattern, section_content)

        for href in href_matches:
            # Split the href by "/" and check if it has exactly 4 parts
            parts = href.split('/')
            if len(parts) == 4 and parts[0] == '' and parts[1] == 'artifact':
                # Join the last 2 parts with ":"
                group_id = parts[2]
                artifact_id = parts[3]
                artifact_full = f"{group_id}:{artifact_id}"
                artifacts.add(artifact_full)

        return list(artifacts)

    def get_deps_dev_default_version(self, system: str, pkg: str) -> Optional[str]:
        """Get default version for a package from deps.dev API"""
        url = f"https://api.deps.dev/v3alpha/systems/{system}/packages/{self.url_encode(pkg)}"

        try:
            response = self.session.get(url)
            if response.status_code != 200:
                logger.warning(
                    f"Failed to get default version for {pkg}: {response.status_code} - "
                    f"{response.reason} - {response.text[:200]}"
                )
                return None

            data = response.json()
            for version in data.get('versions', []):
                if version.get('isDefault'):
                    return version.get('versionKey', {}).get('version')

            logger.warning(f"No default version found for {pkg}")
            return None

        except Exception as e:
            logger.error(f"Error getting default version for {pkg}: {e}")
            return None

    def get_deps_dev_dependencies(self, system: str, pkg: str, version: str) -> List[str]:
        """Get dependencies for a package version from deps.dev API"""
        encoded_pkg = self.url_encode(pkg)
        encoded_version = self.url_encode(version)
        url = (f"https://api.deps.dev/v3alpha/systems/{system}/packages/{encoded_pkg}/"
               f"versions/{encoded_version}:dependencies")

        try:
            response = self.session.get(url)
            if response.status_code != 200:
                response_text = response.text[:500]  # Limit to 500 characters to avoid overly verbose logs
                logger.warning(f"Failed to get dependencies for {pkg}@{version}: {response.status_code}. "
                               f"Response: {response_text}")
                return []

            data = response.json()
            result_deps = []

            for node in data.get('nodes', []):
                version_key = node.get('versionKey', {})
                if all(k in version_key for k in ['system', 'name', 'version']):
                    purl = f"pkg:{version_key['system'].lower()}/{version_key['name']}@{version_key['version']}"
                    result_deps.append(purl)

            return result_deps

        except Exception as e:
            logger.error(f"Error getting dependencies for {pkg}@{version}: {e}")
            return []

    def repo_url_to_purl(self, url: str) -> Optional[str]:
        """Convert repository URL to PURL format"""
        try:
            if url.startswith("https://github.com/"):
                parts = url.replace("https://github.com/", "").split("/")
                if len(parts) >= 2:
                    owner = parts[0]
                    repo = parts[1].replace(".git", "")
                    return f"pkg:github/{owner}/{repo}"

            elif "git@github.com" in url:
                # Extract from git@github.com:owner/repo.git format
                match = re.search(r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$', url)
                if match:
                    owner, repo = match.groups()
                    return f"pkg:github/{owner}/{repo}"

            elif url.startswith("github.com/"):
                parts = url.replace("github.com/", "").split("/")
                if len(parts) >= 2:
                    owner = parts[0]
                    repo = parts[1]
                    return f"pkg:github/{owner}/{repo}"

            elif url.startswith("https://gitbox.apache.org/"):
                parts = url.replace("https://gitbox.apache.org/", "").split("/")
                if len(parts) >= 1 and parts[0] == "repos":
                    owner = "apache"
                    if len(parts) == 2:
                        repo = parts[1].split("=")[-1] if "=" in parts[1] else parts[1]
                    elif len(parts) >= 3:
                        repo = parts[2]
                    else:
                        return None
                    repo = repo.replace(".git", "")
                    return f"pkg:github/{owner}/{repo}"

            # If we can't parse it, return None
            return None

        except Exception as e:
            logger.warning(f"Error converting repo url to purl: {url}, error: {e}")
            return None

    def get_purl_github_repos(self, purls: List[str]) -> Dict[str, str]:
        """Convert PURLs to GitHub repository PURLs using deps.dev API"""
        purl_to_repo_purl = {}

        # Process in batches to avoid overwhelming the API
        batch_size = 100
        for i in range(0, len(purls), batch_size):
            batch = purls[i:i + batch_size]
            logger.info(f"Processing PURL batch {i+1}-{min(i+batch_size, len(purls))} of {len(purls)}...")

            for purl in batch:
                try:
                    # Parse the purl to get system, name, and version
                    if not purl.startswith('pkg:'):
                        continue

                    parts = purl[4:].split('/')
                    if len(parts) < 2:
                        continue

                    system = parts[0]
                    name_version = '/'.join(parts[1:])

                    if '@' in name_version:
                        name, version = name_version.rsplit('@', 1)
                    else:
                        continue

                    # Get package info from deps.dev
                    encoded_name = self.url_encode(name)
                    encoded_version = self.url_encode(version)
                    url = (f"https://api.deps.dev/v3alpha/systems/{system}/packages/"
                           f"{encoded_name}/versions/{encoded_version}")
                    response = self.session.get(url)

                    if response.status_code != 200:
                        continue

                    data = response.json()
                    repo_url = None

                    # Look for source repo in related projects
                    for project in data.get('relatedProjects', []):
                        if project.get('relationType') == 'SOURCE_REPO':
                            repo_url = project.get('projectKey', {}).get('id')
                            break
                        elif project.get('relationType') == 'ISSUE_TRACKER' and not repo_url:
                            repo_url = project.get('projectKey', {}).get('id')

                    # If not found in related projects, check links
                    if not repo_url:
                        for link in data.get('links', []):
                            if link.get('label') == 'SOURCE_REPO':
                                repo_url = link.get('url')
                                break

                    if repo_url:
                        repo_purl = self.repo_url_to_purl(repo_url)
                        if repo_purl:
                            purl_to_repo_purl[purl] = repo_purl
                        else:
                            logger.warning(f"Could not convert repo URL to PURL: {repo_url}")

                except Exception as e:
                    logger.warning(f"Error processing PURL {purl}: {e}")
                    continue

            # Small delay between batches to be respectful to the API
            time.sleep(0.1)

        return purl_to_repo_purl

    def scrape_mvn_and_output_json(self, output_file: str) -> bool:
        """Main function to scrape Maven packages and output to JSON"""
        logger.info("Starting Maven package scraping...")

        # Step 1: Scrape popular packages
        logger.info("Scraping popular Maven packages...")
        all_packages = []

        for i in range(1, 21):  # Pages 1-20
            packages = self.get_mvn_popular_page(i)
            all_packages.extend(packages)
            logger.info(f"Scraped page {i}, found {len(packages)} packages")

        logger.info(f"Total popular packages found: {len(all_packages)}")

        # Step 2: Get dependencies for all packages
        logger.info("Getting dependencies for popular packages...")
        all_dependencies = set()
        failed_lookups = 0
        packages_with_deps = 0

        for i, pkg in enumerate(all_packages):
            if i % 50 == 0:
                logger.info(f"Processing package {i+1}/{len(all_packages)}...")

            # Get default version
            version = self.get_deps_dev_default_version("maven", pkg)
            if not version:
                logger.warning(f"Failed to get default version for {pkg}")
                failed_lookups += 1
                continue

            # Get dependencies
            deps = self.get_deps_dev_dependencies("maven", pkg, version)
            if not deps:
                failed_lookups += 1
            else:
                packages_with_deps += 1
                all_dependencies.update(deps)

        dependencies_list = sorted(list(all_dependencies))
        logger.info(f"Total unique dependencies found: {len(dependencies_list)}")

        # Step 3: Convert PURLs to GitHub repositories
        logger.info("Converting PURLs to GitHub repositories...")
        purl_to_repo_purl = self.get_purl_github_repos(dependencies_list)

        github_repos = sorted(list(set(purl_to_repo_purl.values())))
        logger.info(f"Total GitHub repositories found: {len(github_repos)}")

        # Create results structure
        results = {
            "popular_packages": all_packages,
            "dependencies": dependencies_list,
            "github_repositories": github_repos,
            "statistics": {
                "total_popular_packages": len(all_packages),
                "total_dependencies": len(dependencies_list),
                "total_github_repos": len(github_repos),
                "packages_with_dependencies": packages_with_deps,
                "failed_dependency_lookups": failed_lookups
            },
            "metadata": {
                "scraped_at": str(int(time.time())),
                "pages_scraped": 20,
                "source_system": "mvnrepository.com",
                "dependency_system": "maven"
            }
        }

        # Write to JSON file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            logger.info(f"Results written to {output_file}")
            summary = (f"Summary: {len(all_packages)} popular packages, "
                       f"{len(dependencies_list)} dependencies, {len(github_repos)} GitHub repos")
            logger.info(summary)
            return True

        except Exception as e:
            logger.error(f"Failed to write JSON file: {e}")
            return False


def main():
    scraper = MavenScraper()
    # Get the correct path to the resources directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    resources_dir = os.path.join(script_dir, "..", "resources")
    output_file = os.path.join(resources_dir, "top_maven_packages.json")

    success = scraper.scrape_mvn_and_output_json(output_file)
    if not success:
        exit(1)


if __name__ == "__main__":
    main()
