from typing import Optional
import os
import sys
import subprocess
import xml.etree.ElementTree as ET

from guarddog.analyzer.metadata.detector import Detector

OUTPUT_FILE = "effective-pom.xml"
NAMESPACE = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
DANGEROUS_PLUGINS = {
            "exec-maven-plugin",
            "maven-antrun-plugin",
            "groovy-maven-plugin",
            "jruby-maven-plugin",
            "jython-maven-plugin",
            "maven-site-plugin"
        }
URL_PATHS = [
        ".//mvn:repository/mvn:url",
        ".//mvn:pluginRepository/mvn:url",
        ".//mvn:distributionManagement/mvn:repository/mvn:url",
        ".//mvn:distributionManagement/mvn:snapshotRepository/mvn:url",
        ".//mvn:scm/mvn:url",
        ]

class MavenDangerousPomXML(Detector): 
    def __init__(self):
        super().__init__(
            name="dangerous_pom_xml",
            description="Detects pom.xml files with dangerous configuration: unsafe protocol usage, dangerous plugins, code execution in lifecycle phases"
        )

    def detect(self, package_info = None, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
            Detects dangerous behaviours defined in the effective pom.xml of the java project in path
        """
        # must return a bool, message
        if path is None:
            raise ValueError("path is needed to run heuristic " + self.get_name())
        message: str = ""
        result = False
        effective_pom_path: str = self.get_effective_pom(path)
        if not os.path.isfile(effective_pom_path):
            print(f"Error: No  effective pom found in '{effective_pom_path}'.")
            sys.exit(1)

        http_unsafe: bool = self.http_unsafe(effective_pom_path)
        if http_unsafe:
            message += f"\nUnsafe http usage detected in {os.path.abspath(effective_pom_path)}.\n"
            result = True

        untrusted_plugin_source, unstrusted_urls = self.untrusted_download_source(effective_pom_path)
        if untrusted_plugin_source: 
            message += f"\nPlugin(s) downloaded from unstructed source(s): \n"
            for bad_url in unstrusted_urls:
                message += f"\t - {bad_url}\n"
            result = True 

        malicious_plugin_found, malicious_plugins_list  = self.is_malicious_plugin(effective_pom_path)
        if malicious_plugin_found: 
            message += "\nSuspicious plugins affecting lifecycle phases found: \n"
            for plugin in malicious_plugins_list: 
                message += f"\t - {plugin}\n"
            result = True

        print("\n\n")
        print("-"*50)
        print(f"Findings in the target {path}")
        print("-"*50)
        print(message)



        

    def get_effective_pom(self, path: str) -> str: 
        """
            Get the effective pom.xml file of the project in path. The pom.xml is supposed to be in the root directory: {path}/pom.xml
            Stores the resulting effective xml in OUTPUT_FILE
        """
        if not os.path.isdir(path):
            print(f"Error: The path '{path}' is not a valid directory.")
            sys.exit(1)

        pom_path = os.path.join(path, "pom.xml")

        if not os.path.isfile(pom_path):
            print(f"Error: No 'pom.xml' found in '{path}'. Please provide a valid Maven project directory.")
            sys.exit(1)
        print(f"pom.xml found at {path}/ ")

        command = ["mvn", "help:effective-pom", f"-Doutput={OUTPUT_FILE}"]
        effective_pom_path = os.path.join(path, OUTPUT_FILE)

        try:
            # create the effective pom xml
            result = subprocess.run(
                command,
                cwd=path,
                check=True,
                capture_output=True,
                text=True
            )
            if os.path.exists(effective_pom_path):
                print(f"Effective POM generated at: {os.path.abspath(effective_pom_path)}")
            else:
                # This case is unlikely if `check=True` is used, but serves as a fallback.
                print("Error: Maven command executed, but the output file was not created.")
                sys.exit(1)
            return effective_pom_path
        
        except FileNotFoundError:
            print("Error: 'mvn' command not found. Please ensure Apache Maven is installed and in your system's PATH.")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print("Error: Maven command failed to execute.")
            print("\n--- Maven Error Output ---")
            print(e.stderr)
            print("--------------------------")
            sys.exit(1)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            sys.exit(1)





    def http_unsafe(self, pom_path: str) -> bool: 
        """
        Detects unsafe http protocol in the effective pom.xml to get a custom plugin
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()

        print("Scanning for insecure HTTP URLs...\n")
        found = False
        for path in URL_PATHS:
            for elem in root.findall(path, NAMESPACE):
                url = self.get_text(elem)
                if url.startswith("http://"):
                    print(f"Insecure URL found: {url} in the effective pom.xml {pom_path}.")
                    found = True

        if not found:
            print("No insecure HTTP URLs found in the effective pom.xml.")
        return found
    
    def untrusted_download_source(self, pom_path: str)-> tuple[bool, list[str]] : 
        """ 
            Detects when a custom plugin in <repository> or <pluginRepository> is not downloaded from https://repo.maven.apache.org/maven2
            Returns a boolean and a list of detected not conform urls
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        print("Scanning for unstrusted plugins downloads...\n")
        found = False
        bad_urls = []
        download_urls = [
        ".//mvn:repository/mvn:url",
        ".//mvn:pluginRepository/mvn:url"
        ]
        for path in download_urls:
            for elem in root.findall(path, NAMESPACE):
                url = self.get_text(elem)
                if not url.startswith("https://repo.maven.apache.org"):
                    found = True
                    bad_urls.append(url)
                    print(f"Untrusted plugin source {url}.")
        return found, bad_urls


    def get_text(self, elem):
        return elem.text.strip() if elem is not None and elem.text else ""

    def is_malicious_plugin(self, pom_path: str)-> tuple[bool, list]:
        """ Detects suspicious plugins in effective pom.xml using an exhaustive list of plugins in Java able to execute code in lifecycle phases 
            Returns a bool and
        """
        tree = ET.parse(pom_path)
        root = tree.getroot()
        print("Scanning for dangerous plugins ...\n")
        results = []
        suspicious_plugin_found = False

        for plugin in root.findall(".//mvn:plugin", NAMESPACE):
            artifact_id = plugin.find("mvn:artifactId", NAMESPACE)
            plugin_id = self.get_text(artifact_id)
            if plugin_id in DANGEROUS_PLUGINS:
                suspicious_plugin_found = True
                results.append(plugin_id)
                print(f"Suspicious plugin found: {plugin_id} in the effective pom.xml {pom_path}.")
        if not suspicious_plugin_found: 
            print(f"No suspicious plugin found in the effective pom.xml {pom_path}.")
        return suspicious_plugin_found, results

    
        
