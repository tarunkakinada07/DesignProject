"""CLI script to ingest datasets and update Sentinel SQLite database."""

import argparse
import sys
from pathlib import Path

# Bootstrap repository root on python path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.app.database.connection import init_db
from ml.collection.audit import dataset_quality_summary
from ml.collection.dedup import run_deduplication_and_clustering
from ml.collection.importers import (
    import_chrome_mal_ids,
    import_local_package,
    import_sentry_ioc_records,
)


def main():
    parser = argparse.ArgumentParser(description="Ingest threat intelligence and extension samples.")
    parser.add_argument("--tpci-csv", type=Path, help="Path to local chrome-mal-ids CSV file")
    parser.add_argument("--sentry-json", type=Path, help="Path to local malicious_extension_sentry JSON file")
    parser.add_argument("--package-dir", type=Path, help="Directory containing .crx or .zip packages to ingest")
    parser.add_argument("--package-label", choices=["malicious", "benign", "suspicious"], default="benign")
    parser.add_argument("--fetch-online", action="store_true", help="Attempt online fetch of open IOC feeds")

    args = parser.parse_args()

    init_db()
    print("Database initialized.")

    if args.tpci_csv and args.tpci_csv.is_file():
        inserted, total = import_chrome_mal_ids(args.tpci_csv)
        print(f"Imported chrome-mal-ids: {inserted} new records from {total} rows.")
    elif args.fetch_online:
        print("Fetching online chrome-mal-ids feed...")
        inserted, total = import_chrome_mal_ids()
        print(f"Imported chrome-mal-ids: {inserted} records.")

    if args.sentry_json and args.sentry_json.is_file():
        inserted, total = import_sentry_ioc_records(args.sentry_json)
        print(f"Imported sentry IOCs: {inserted} new records from {total} rows.")
    elif args.fetch_online:
        print("Fetching online sentry IOC feed...")
        inserted, total = import_sentry_ioc_records()
        print(f"Imported sentry IOCs: {inserted} records.")

    if args.package_dir and args.package_dir.is_dir():
        count = 0
        for p in args.package_dir.glob("*.*"):
            if p.suffix.lower() in {".crx", ".zip"}:
                rec = import_local_package(p, label=args.package_label)
                if rec:
                    count += 1
        print(f"Imported {count} local packages from {args.package_dir}.")

    # Run deduplication and clustering
    dedup_res = run_deduplication_and_clustering()
    print("Clustering complete:", dedup_res)

    summary = dataset_quality_summary()
    print("\n=== Dataset Quality Summary ===")
    for k, v in summary.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    sys.exit(main())
