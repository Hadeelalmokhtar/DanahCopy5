import os
import shutil
import tempfile
from pathlib import Path

class PackageAdapter:
    """
    Builds a minimal SAP-like package structure from a single file:
    temp/<package_name>/1.0/<original_file>
    """
    def build_from_single_file(self, file_path: str) -> str:
        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        temp_dir = tempfile.mkdtemp(prefix="sap_pkg_")
        package_name = Path(file_path).stem
        package_root = os.path.join(temp_dir, package_name, "1.0")

        os.makedirs(package_root, exist_ok=True)
        shutil.copy(file_path, os.path.join(package_root, Path(file_path).name))

        return temp_dir
