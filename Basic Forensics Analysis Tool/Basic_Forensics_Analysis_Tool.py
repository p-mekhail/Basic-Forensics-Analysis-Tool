import os
import hashlib
import argparse
from datetime import datetime

# Optional: You can install and use exiftool and pytsk3 for more advanced features


def calculate_hash(file_path, algo='sha256'):
    h = hashlib.new(algo)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def list_files(directory):
    files_info = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                stat = os.stat(full_path)
                files_info.append({
                    'file': full_path,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'hash': calculate_hash(full_path)
                })
            except Exception as e:
                print(f"[ERROR] Cannot access {full_path}: {e}")
    return files_info


def generate_report(files_info, report_path='forensics_report.txt'):
    with open(report_path, 'w') as f:
        for info in files_info:
            f.write(f"File: {info['file']}\n")
            f.write(f"Size: {info['size']} bytes\n")
            f.write(f"Modified: {info['modified']}\n")
            f.write(f"SHA-256: {info['hash']}\n")
            f.write("-" * 40 + "\n")
    print(f"[INFO] Report saved to {report_path}")


def process_target(target, report):
    if os.path.isfile(target):
        file_info = [{
            'file': target,
            'size': os.path.getsize(target),
            'modified': datetime.fromtimestamp(os.path.getmtime(target)),
            'hash': calculate_hash(target)
        }]
    elif os.path.isdir(target):
        file_info = list_files(target)
    else:
        print("[ERROR] Invalid target specified.")
        return

    generate_report(file_info, report)


def main():
    while True:
        target = input("Enter path to analyze (file or folder): ").strip()
        if not target:
            print("[ERROR] Target path is required.")
            continue

        report = input("Enter path to save report (leave blank for default): ").strip()
        if not report:
            report = "forensics_report.txt"

        try:
            process_target(target, report)
        except Exception as e:
            print(f"[EXCEPTION] Something went wrong: {e}")

        again = input("Do you want to scan another file or folder? (y/n): ").strip().lower()
        if again != 'y':
            print("[INFO] Exiting the program.")
            break


if __name__ == '__main__':
    main()

