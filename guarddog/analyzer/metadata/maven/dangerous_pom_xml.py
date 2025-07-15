from typing import Optional
import os
import sys
import subprocess

from guarddog.analyzer.metadata.detector import Detector

OUTPUT_FILE = "effective-pom.xml"

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
        if path is None:
            raise ValueError("path is needed to run heuristic " + self.get_name())
        self.get_effective_pom(path)
        print("effective pom generated")
        

    def get_effective_pom(self, path: str): 
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
        output_path = os.path.join(path, OUTPUT_FILE)

        try:
            # create the effective pom xml
            result = subprocess.run(
                command,
                cwd=path,
                check=True,
                capture_output=True,
                text=True
            )
            if os.path.exists(output_path):
                print(f"Effective POM generated at: {os.path.abspath(output_path)}")
            else:
                # This case is unlikely if `check=True` is used, but serves as a fallback.
                print("Error: Maven command executed, but the output file was not created.")
                sys.exit(1)
        
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


        
        
