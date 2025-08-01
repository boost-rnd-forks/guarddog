import logging
import os
import stat
import zipfile
import subprocess

import tarsafe  # type:ignore

log = logging.getLogger("guarddog")
CFR_JAR_PATH = os.environ.get(
    "CFR_JAR_PATH",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../cfr-0.152.jar")),
)


def is_supported_archive(path: str) -> bool:
    """
    Decide whether a file contains a supported archive based on its
    file extension.

    Args:
        path (str): The local filesystem path to examine

    Returns:
        bool: Represents the decision reached for the file

    """

    def is_tar_archive(path: str) -> bool:
        tar_exts = [".bz2", ".bzip2", ".gz", ".gzip", ".tgz", ".xz"]

        return any(path.endswith(ext) for ext in tar_exts)

    def is_zip_archive(path: str) -> bool:
        return any(path.endswith(ext) for ext in [".zip", ".whl", ".egg"])

    return is_tar_archive(path) or is_zip_archive(path)


def safe_extract(source_archive: str, target_directory: str) -> None:
    """
    safe_extract safely extracts archives to a target directory.

    This function does not clean up the original archive and does not
    create the target directory if it does not exist.  It also assumes
    the source archive argument is a path to a regular file on the
    local filesystem.

    @param source_archive:      The archive to extract
    @param target_directory:    The directory where to extract the archive to
    @raise ValueError           If the archive type is unsupported

    """
    log.debug(f"Extracting archive {source_archive} to directory {target_directory}")
    if tarsafe.is_tarfile(source_archive):

        def add_exec(path):
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IEXEC)

        def add_read(path):
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IREAD)

        def recurse_add_perms(path):
            add_exec(path)
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    add_exec(os.path.join(root, d))
                for f in files:
                    add_read(os.path.join(root, f))

        tarsafe.open(source_archive).extractall(target_directory)
        recurse_add_perms(target_directory)

    elif zipfile.is_zipfile(source_archive):
        with zipfile.ZipFile(source_archive, "r") as zip:
            for file in zip.namelist():
                # Note: zip.extract cleans up any malicious file name
                # such as directory traversal attempts This is not the
                # case of zipfile.extractall
                zip.extract(file, path=os.path.join(target_directory, file))
    else:
        raise ValueError(f"unsupported archive extension: {source_archive}")


def extract_jar(jar_path: str, output_dir: str):
    """
    Extract a jar archive file with zipfile
    - `jar_path` (str): path to the jar to extract
    - `output_dir` (str): directory to decompress the jar to
    """
    with zipfile.ZipFile(jar_path, "r") as jar:
        log.debug("Extracting jar package...")
        output_dir_abs = os.path.abspath(output_dir)
        for file in jar.namelist():
            # resolve paths and removes ../
            safe_path = os.path.abspath(os.path.join(output_dir, file))
            # ensure safe_path in the output dir
            if os.path.commonpath([output_dir_abs, safe_path]) != output_dir_abs:
                log.warning(f"Skipping potentially unsafe file: {file}")
                continue
            if file.endswith("/"):  # It's a directory
                os.makedirs(safe_path, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
            with open(safe_path, "wb") as f:
                f.write(jar.read(file))
    log.debug(f"extracted to {output_dir}")


def is_safe_path(path: str) -> bool:
    """Basic path safety check to avoid traversal or injection."""
    return os.path.isabs(path) or not (".." in path or path.startswith(("/", "\\")))


def is_jar_file(path: str) -> bool:
    return path.endswith(".jar") and os.path.isfile(path)


def decompile_jar(jar_path: str, dest_path: str):
    """
    Decompiles the .jar file using CFR decompiler.
    Args:
        - `jar_path` (str): path of the .jar to decompile
        - `dest_path` (str): path of the destination folder
        to store the resulting .class files
    """
    if not is_safe_path(jar_path) or not is_jar_file(jar_path):
        raise ValueError(f"Invalid JAR path: {jar_path}")
    if not os.path.isfile(CFR_JAR_PATH):
        raise FileNotFoundError(f"CFR jar file not found: {CFR_JAR_PATH}")
    if not is_safe_path(dest_path):
        raise ValueError(f"Invalid destination path: {dest_path}")

    os.makedirs(dest_path, exist_ok=True)

    command = [
        "java",
        "-jar",
        CFR_JAR_PATH,
        jar_path,
        "--outputdir",
        dest_path,
        "--silent",
        "true",
    ]

    try:
        subprocess.run(command, check=True)
        log.debug(f"Decompiled JAR written to: {os.path.abspath(dest_path)}")
    except subprocess.CalledProcessError as e:
        log.error(f"Error running CFR: {e}")
