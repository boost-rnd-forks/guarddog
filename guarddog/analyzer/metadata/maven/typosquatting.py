import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION

log = logging.getLogger("guarddog")


class MavenTyposquatDetector(TyposquatDetector):
    """Detector for typosquatting attacks for Maven packages. Checks for
    distance one Levenshtein, one-off character swaps, permutations around
    hyphens, and substrings.

    Attributes:
        popular_packages (set): set of top Maven packages with 30-day caching,
          stored in resources/top_maven_packages.json and updated every 30 days
    """

    def _get_top_packages(self) -> set:
        """
        Gets Maven packages using the same 30-day caching pattern as PyPI
        and NPM. Automatically calls Maven scraper when cache is stale.

        Returns:
            set: Set of popular Maven packages in "groupId:artifactId" format
        """
        top_packages_filename = "top_maven_packages.json"

        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "resources")
            )

        top_packages_path = os.path.join(resources_dir, top_packages_filename)

        # Check if file exists and is recent (< 30 days old)
        should_refresh = True
        if os.path.exists(top_packages_path):
            update_time = datetime.fromtimestamp(
                os.path.getmtime(top_packages_path))

            if datetime.now() - update_time <= timedelta(days=30):
                log.debug(
                    f"Using cached Maven packages from {top_packages_path}")
                try:
                    with open(top_packages_path, "r") as top_packages_file:
                        data = json.load(top_packages_file)
                    
                    packages = self._extract_packages_from_data(data)
                    if packages:
                        should_refresh = False
                        return packages
                    else:
                        log.warning("Cached file is empty or invalid")
                except Exception as e:
                    log.warning(f"Failed to read cached file: {e}")

        # If no recent cache or file is invalid, run Maven scraper
        if should_refresh:
            log.info("Cache missing or stale. Running Maven scraper...")
            success = self._run_maven_scraper(top_packages_path)
            
            if success:
                # Read the newly generated file
                try:
                    with open(top_packages_path, "r") as top_packages_file:
                        data = json.load(top_packages_file)
                    
                    packages = self._extract_packages_from_data(data)
                    if packages:
                        return packages
                    else:
                        log.warning("Newly generated file is empty or invalid")
                except Exception as e:
                    log.warning(f"Failed to read newly generated file: {e}")
            else:
                log.warning("Maven scraper failed")

        # Final fallback if everything fails
        log.warning(
            "All package sources failed, using essential packages as fallback"
        )
        return self._get_essential_maven_packages()

    def _extract_packages_from_data(self, data) -> set:
        """
        Extract Maven packages from JSON data (handles both formats).
        
        Args:
            data: JSON data (either list or structured dict)
            
        Returns:
            set: Set of Maven package names
        """
        packages = set()
        
        # Handle both old format (simple array) and new format (structured JSON)
        if isinstance(data, list):
            # Old format: simple array of package names
            log.debug("Using legacy format (simple array)")
            packages.update(data)
        elif isinstance(data, dict):
            # New format: structured JSON with popular_packages
            log.debug("Using new structured format")
            popular_packages = data.get("popular_packages", [])
            packages.update(popular_packages)
            
            # Also add Maven packages from dependencies if available
            dependencies = data.get("dependencies", [])
            maven_deps = set()
            for dep in dependencies:
                if dep.startswith('pkg:maven/'):
                    # Extract package name from PURL: pkg:maven/groupId:artifactId@version
                    maven_part = dep[10:]  # Remove 'pkg:maven/'
                    if '@' in maven_part:
                        package_name = maven_part.split('@')[0]  # Remove version
                        # Convert slashes to colons for proper Maven format
                        package_name = package_name.replace('/', ':')
                        maven_deps.add(package_name)
            
            packages.update(maven_deps)
            log.debug(f"Loaded {len(popular_packages)} popular packages + {len(maven_deps)} from dependencies")
        
        return packages

    def _run_maven_scraper(self, output_file: str) -> bool:
        """
        Run the Maven scraper to generate fresh package data.
        
        Args:
            output_file: Path where to save the scraped data
            
        Returns:
            bool: True if scraping succeeded, False otherwise
        """
        try:
            # Import the Maven scraper
            from guarddog.analyzer.metadata.maven.maven_scraper import MavenScraper
            
            log.info("Initializing Maven scraper...")
            scraper = MavenScraper()
            
            log.info("Starting Maven package scraping (this may take a few minutes)...")
            success = scraper.scrape_mvn_and_output_json(output_file)
            
            if success:
                log.info("✅ Maven scraper completed successfully!")
                return True
            else:
                log.error("❌ Maven scraper failed")
                return False
                
        except ImportError as e:
            log.error(f"Failed to import Maven scraper: {e}")
            return False
        except Exception as e:
            log.error(f"Error running Maven scraper: {e}")
            return False

    def _get_essential_maven_packages(self) -> set:
        """
        Returns a curated set of essential Maven packages as fallback.
        These are the most critical packages that should always be included.

        Returns:
            set: Essential Maven packages
        """
        return {
            # Spring Boot ecosystem (most popular)
            "org.springframework.boot:spring-boot-starter-parent",
            "org.springframework.boot:spring-boot-starter-web",
            "org.springframework.boot:spring-boot-starter-data-jpa",
            "org.springframework.boot:spring-boot-starter-test",
            "org.springframework.boot:spring-boot-starter-security",
            "org.springframework.boot:spring-boot-starter-actuator",

            # Core Spring
            "org.springframework:spring-core",
            "org.springframework:spring-context",
            "org.springframework:spring-web",
            "org.springframework:spring-webmvc",

            # Testing
            "org.junit.jupiter:junit-jupiter",
            "org.junit.jupiter:junit-jupiter-api",
            "org.junit.jupiter:junit-jupiter-engine",
            "org.mockito:mockito-core",
            "org.testng:testng",

            # Logging
            "org.slf4j:slf4j-api",
            "ch.qos.logback:logback-classic",
            "org.apache.logging.log4j:log4j-core",

            # JSON processing
            "com.fasterxml.jackson.core:jackson-core",
            "com.fasterxml.jackson.core:jackson-databind",
            "com.google.code.gson:gson",

            # Utilities
            "com.google.guava:guava",
            "org.apache.commons:commons-lang3",
            "org.projectlombok:lombok",

            # Database
            "mysql:mysql-connector-java",
            "org.postgresql:postgresql",
            "com.h2database:h2",
            "org.hibernate.orm:hibernate-core",

            # HTTP clients
            "org.apache.httpcomponents:httpclient",
            "com.squareup.okhttp3:okhttp",
        }

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Uses a Maven package's information to determine if the package is
        attempting a typosquatting attack

        Args:
            package_info (dict): dictionary containing Maven package
                information with 'info' key containing 'groupid' and
                'artifactid'
            name (str): The name of the package in format "groupId:artifactId"

        Returns:
            Tuple[bool, Optional[str]]: True if package is typosquatted,
               along with a message indicating the similar package name.
               False if not typosquatted and None
        """
        # Construct the full package name from package_info if name is not
        # provided
        if name is None:
            group_id = package_info.get("info", {}).get("groupid", "")
            artifact_id = package_info.get("info", {}).get("artifactid", "")
            if group_id and artifact_id:
                name = f"{group_id}:{artifact_id}"
            else:
                return False, (
                    "Could not determine package name from package info")

        log.debug(f"Running typosquatting heuristic on Maven package {name}")
        similar_package_names = self.get_typosquatted_package(name)
        if len(similar_package_names) > 0:
            return True, TyposquatDetector.MESSAGE_TEMPLATE % ", ".join(
                similar_package_names
            )
        return False, None

    def _get_confused_forms(self, package_name) -> list:
        """
        Gets confused terms for Maven packages
        Confused terms are:
            - org.apache.* to org.springframework.* swaps (or vice versa)
            - com.google.* to com.apache.* swaps
            - Group ID hierarchy confusions (org.junit vs junit)
            - Common Maven group ID patterns and sub-groups
            - Artifact ID term swaps (core/api, spring/apache, etc.)

        Args:
            package_name (str): name of the package in format
                "groupId:artifactId"

        Returns:
            list: list of confused terms
        """
        confused_forms = []

        if ":" not in package_name:
            return confused_forms

        group_id, artifact_id = package_name.split(":", 1)

        # Enhanced group ID confusions with pattern matching
        group_id_patterns = {
            # Apache ecosystem confusions
            "org.apache": ["org.springframework", "com.apache"],
            "org.apache.commons": ["org.springframework", "com.google.common",
                                   "org.apache"],
            "org.apache.logging": ["org.slf4j", "ch.qos.logback"],
            "org.apache.httpcomponents": ["com.squareup.okhttp3",
                                          "org.springframework.web"],

            # Spring ecosystem confusions
            "org.springframework": ["org.apache", "org.apache.commons",
                                    "com.springframework"],
            "org.springframework.boot": ["org.springframework",
                                         "org.apache.commons"],
            "org.springframework.data": ["org.hibernate",
                                         "org.apache.commons"],

            # Google ecosystem confusions
            "com.google": ["com.apache", "org.google", "com.google.guava"],
            "com.google.guava": ["org.apache.commons", "com.google"],
            "com.google.code": ["org.apache", "com.google"],

            # Testing framework confusions
            "org.junit": ["junit", "com.junit", "org.testng"],
            "junit": ["org.junit", "org.testng"],
            "org.testng": ["org.junit", "junit"],
            "org.mockito": ["com.mockito", "org.junit", "org.testng"],

            # Logging framework confusions
            "org.slf4j": ["ch.qos.logback", "org.apache.logging.log4j"],
            "ch.qos.logback": ["org.slf4j", "org.apache.logging.log4j"],
            "org.apache.logging.log4j": ["org.slf4j", "ch.qos.logback"],

            # Hibernate/JPA confusions
            "org.hibernate": ["com.hibernate", "org.springframework.data",
                              "javax.persistence"],
            "javax.persistence": ["org.hibernate", "org.springframework.data"],

            # Jackson confusions
            "com.fasterxml.jackson": ["com.fasterxml.jackson.core",
                                      "org.codehaus.jackson"],
            "com.fasterxml.jackson.core": ["com.fasterxml.jackson",
                                           "org.codehaus.jackson"],
            "com.fasterxml": ["com.fasterxml.jackson"],

            # Database driver confusions
            "mysql": ["org.mysql", "com.mysql"],
            "org.postgresql": ["postgresql", "com.postgresql"],
        }

        # Generate confused forms based on exact and pattern matches
        for pattern_group, confused_groups in group_id_patterns.items():
            if group_id == pattern_group:
                # Exact match
                for confused_group in confused_groups:
                    confused_forms.append(f"{confused_group}:{artifact_id}")
            elif group_id in confused_groups:
                # Reverse mapping
                confused_forms.append(f"{pattern_group}:{artifact_id}")
            elif group_id.startswith(pattern_group + "."):
                # Sub-group pattern matching (e.g., org.apache.* →
                # org.springframework.*)
                for confused_group in confused_groups:
                    if not confused_group.startswith(
                            group_id[:group_id.rfind(".")]):
                        confused_forms.append(
                            f"{confused_group}:{artifact_id}")

        # Handle hierarchical group ID simplifications/expansions
        group_parts = group_id.split(".")
        if len(group_parts) > 2:
            # Try simplified versions (e.g., org.apache.commons → org.apache)
            simplified = ".".join(group_parts[:-1])
            confused_forms.append(f"{simplified}:{artifact_id}")

            # Try root level (e.g., org.apache.commons → apache)
            if len(group_parts) >= 2:
                root = group_parts[-2]  # Get the main organization name
                confused_forms.append(f"{root}:{artifact_id}")

        # Handle artifact ID pattern confusions
        artifact_terms = artifact_id.split("-")

        # Enhanced artifact term confusions
        artifact_confusions = {
            "spring": ["apache", "hibernate"],
            "apache": ["spring", "commons"],
            "core": ["api", "common", "base"],
            "api": ["core", "common", "interface"],
            "common": ["core", "api", "utils"],
            "utils": ["common", "core", "tools"],
            "client": ["server", "api", "core"],
            "server": ["client", "api", "core"],
            "web": ["rest", "http", "api"],
            "rest": ["web", "http", "api"],
            "boot": ["core", "spring", "auto"],
            "auto": ["boot", "config", "core"],
            "test": ["testing", "junit", "mock"],
            "mock": ["test", "mockito", "fake"],
            "starter": ["boot", "spring", "auto"],
        }

        for i, term in enumerate(artifact_terms):
            for original_term, confused_terms in artifact_confusions.items():
                if original_term in term:
                    # Replace term with confused versions
                    for confused_term in confused_terms:
                        new_term = term.replace(original_term, confused_term)
                        if new_term != term:  # Only add if it actually changed
                            replaced_artifact = (
                                artifact_terms[:i] + [new_term]
                                + artifact_terms[i + 1:])
                            confused_forms.append(
                                f"{group_id}:{'-'.join(replaced_artifact)}")

        # Remove duplicates while preserving order
        seen = set()
        unique_confused_forms = []
        for form in confused_forms:
            if (form not in seen
                    and form != package_name):  # Don't include original package
                seen.add(form)
                unique_confused_forms.append(form)

        return unique_confused_forms


if __name__ == "__main__":
    detector = MavenTyposquatDetector()
    packages = detector._get_top_packages()
    print(f"Loaded {len(packages)} Maven packages")
    for pkg in sorted(list(packages))[:10]:
        print(f"  - {pkg}")
