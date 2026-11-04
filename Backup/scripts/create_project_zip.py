"""Create a clean, comprehensive distribution ZIP of the Sentinel Extension project for sharing with AI chatbots."""

import os
from pathlib import Path
import shutil
import zipfile

BASE_DIR = Path(__file__).resolve().parent.parent

EXCLUDE_DIRS = {
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".git",
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".zip",
}


def should_include(rel_path: Path) -> bool:
    """Determine whether a file should be included in the distribution archive."""
    parts = rel_path.parts
    # Exclude unwanted directories
    for p in parts:
        if p in EXCLUDE_DIRS:
            return False
    # Exclude unwanted file extensions
    if rel_path.suffix.lower() in EXCLUDE_EXTENSIONS:
        return False
    return True


def build_distribution_zip():
    zip_name = "Sentinel_Extension_Project.zip"
    local_zip_path = BASE_DIR / zip_name

    print(f"\n=======================================================")
    print(f" BUILDING SENTINEL EXTENSION DISTRIBUTION ARCHIVE")
    print(f"=======================================================\n")

    files_added = 0
    with zipfile.ZipFile(local_zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, dirs, files in os.walk(BASE_DIR):
            # Modify dirs in-place to avoid descending into excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

            for file in sorted(files):
                abs_file = Path(root) / file
                rel_file = abs_file.relative_to(BASE_DIR)

                if should_include(rel_file):
                    zf.write(abs_file, arcname=str(rel_file))
                    files_added += 1

    size_mb = local_zip_path.stat().st_size / (1024 * 1024)
    print(f"[OK] Successfully compressed {files_added} files into {local_zip_path.name}")
    print(f"[OK] Archive size: {size_mb:.2f} MB")

    # Copy to user-accessible locations
    destinations = [
        Path("C:/Users/kakin/OneDrive/Desktop") / zip_name,
        Path("C:/Users/kakin/Downloads") / zip_name,
        Path("C:/Users/kakin/.gemini/antigravity/brain/0e4fd672-40d7-429c-88df-1cbff4a5a2fe") / zip_name,
    ]

    for dest in destinations:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_zip_path, dest)
            print(f"[OK] Copied archive to: {dest}")
        except Exception as e:
            print(f"[!] Notice: Could not copy to {dest}: {e}")

    print("\n=======================================================")
    print(" ALL ARCHIVES GENERATED & READY FOR CHATBOT SHARING")
    print("=======================================================\n")


if __name__ == "__main__":
    build_distribution_zip()
