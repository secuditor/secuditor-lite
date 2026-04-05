# MIT License – Copyright (c) 2025 Menny Levinski

"""
Calculates cryptographic file hashes for integrity verification.
"""

import os
import json
import hashlib

# Static file path (edit this to match your environment)
FILE_PATH = r"C:\Users\User\Desktop\Filename.exe"

def calculate_file_hashes(file_path):
    """
    Calculate MD5, SHA1, SHA256, and SHA512 hashes for the given file.
    """
    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    hash_algos = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256(),
        "SHA512": hashlib.sha512(),
    }

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                for algo in hash_algos.values():
                    algo.update(chunk)
        return {name: algo.hexdigest() for name, algo in hash_algos.items()}

    except Exception as e:
        return {"error": str(e)}

def generate_hash_report(file_path, output_json=False):
    """
    Generate a readable or JSON-formatted hash report.
    """
    result = calculate_file_hashes(file_path)
    if output_json:
        return json.dumps({"file": file_path, "hashes": result}, indent=4)
    else:
        report = f"\nFile: {file_path}\n"
        for algo, digest in result.items():
            report += f"{algo}: {digest}\n"
        return report

# --- Output ---
if __name__ == "__main__":
    print("🔍 Generating Checksum Report")
    print(generate_hash_report(FILE_PATH))

    os.system("pause")
