import argparse
import logging
import os
import re
import secrets
import json
import yaml
import subprocess
import sys
from typing import List, Dict, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define regex patterns for common secrets
SECRET_PATTERNS = {
    "API Key": r"[a-zA-Z0-9_-]{32,45}",  # Example: Looks for strings of alphanumeric characters and underscores
    "Password": r"(password|passwd|pwd|secret)\s*[:=]\s*['\"]?[\w\W]{6,32}['\"]?",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"[\w\/+]{40}",
    "SSH Private Key Header": r"-----BEGIN OPENSSH PRIVATE KEY-----", # More accurate check needed
    "GCP API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xoxb-\d+-\d+-\w+",

}


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans configuration files for embedded secrets.")
    parser.add_argument("filepath", help="Path to the configuration file or directory to scan.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories.")
    parser.add_argument("-e", "--exclude", nargs="+", help="List of directories or files to exclude from the scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-j", "--json-output", help="Path to save JSON output.")

    return parser


def calculate_entropy(data: str) -> float:
    """
    Calculates the entropy of a string.  Used for identifying potential secrets.

    Args:
        data: The string to analyze.

    Returns:
        The entropy of the string.
    """
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def scan_file(filepath: str) -> List[Dict[str, Union[str, int]]]:
    """
    Scans a single file for secrets using regex patterns and entropy analysis.

    Args:
        filepath: The path to the file to scan.

    Returns:
        A list of dictionaries, where each dictionary represents a detected secret.
        Returns an empty list if no secrets are found.
    """
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        for name, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                secret = match.group(0)
                # Check entropy to avoid false positives (e.g., short strings)
                entropy = calculate_entropy(secret)
                if entropy > 4.0:  # Adjust threshold as needed
                    logging.warning(f"Potential {name} found in {filepath} : {secret[:20]}...") # Log only a snippet
                    findings.append({
                        "filepath": filepath,
                        "secret_type": name,
                        "secret": secret,
                        "start_index": match.start(),
                        "end_index": match.end(),
                        "entropy": entropy
                    })


        # Lint the file if it is a YAML or JSON file

        if filepath.endswith((".yaml", ".yml")):
            try:
                result = subprocess.run(['yamllint', filepath], capture_output=True, text=True)
                if result.returncode != 0:
                    logging.warning(f"yamllint found issues in {filepath}: {result.stderr}")
                    findings.append({
                            "filepath": filepath,
                            "secret_type": "YAML Linting Issue",
                            "secret": result.stderr,
                            "start_index": 0,
                            "end_index": len(result.stderr),
                            "entropy": 0.0 #N/A for linting issues
                        })
            except FileNotFoundError:
                logging.warning("yamllint is not installed. Skipping YAML linting.")
            except Exception as e:
                logging.error(f"Error running yamllint on {filepath}: {e}")

        elif filepath.endswith(".json"):
            try:
                result = subprocess.run(['jsonlint', filepath], capture_output=True, text=True)
                if result.returncode != 0:
                    logging.warning(f"jsonlint found issues in {filepath}: {result.stderr}")
                    findings.append({
                            "filepath": filepath,
                            "secret_type": "JSON Linting Issue",
                            "secret": result.stderr,
                            "start_index": 0,
                            "end_index": len(result.stderr),
                            "entropy": 0.0 #N/A for linting issues
                        })

            except FileNotFoundError:
                logging.warning("jsonlint is not installed. Skipping JSON linting.")
            except Exception as e:
                logging.error(f"Error running jsonlint on {filepath}: {e}")


    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
    except IOError as e:
        logging.error(f"Error reading file {filepath}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing {filepath}: {e}")

    return findings


def scan_directory(directory: str, recursive: bool = False, exclude: List[str] = None) -> List[Dict[str, Union[str, int]]]:
    """
    Scans a directory for configuration files and calls scan_file on each file.

    Args:
        directory: The path to the directory to scan.
        recursive: Whether to scan subdirectories recursively.
        exclude: List of directory or file names to exclude.

    Returns:
        A list of dictionaries, where each dictionary represents a detected secret.
    """

    findings = []
    exclude = exclude or []

    try:
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)

            if item in exclude:
                logging.info(f"Skipping excluded item: {item_path}")
                continue

            if os.path.isfile(item_path):
                findings.extend(scan_file(item_path))
            elif os.path.isdir(item_path) and recursive:
                findings.extend(scan_directory(item_path, recursive, exclude))
    except FileNotFoundError:
        logging.error(f"Directory not found: {directory}")
    except OSError as e:
        logging.error(f"Error accessing directory {directory}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing directory {directory}: {e}")

    return findings


def main():
    """
    Main function to parse arguments, scan files/directories, and output results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    filepath = args.filepath
    recursive = args.recursive
    exclude = args.exclude or []
    json_output_path = args.json_output

    if not os.path.exists(filepath):
        logging.error(f"Path does not exist: {filepath}")
        sys.exit(1)

    if os.path.isfile(filepath):
        findings = scan_file(filepath)
    elif os.path.isdir(filepath):
        findings = scan_directory(filepath, recursive, exclude)
    else:
        logging.error(f"Invalid path type: {filepath}")
        sys.exit(1)

    if findings:
        print("Secrets Found:")
        for finding in findings:
            print(f"  File: {finding['filepath']}")
            print(f"  Type: {finding['secret_type']}")
            print(f"  Secret: {finding['secret'][:50]}...")  # Print only a snippet
            print("-" * 20)

        if json_output_path:
            try:
                with open(json_output_path, 'w') as f:
                    json.dump(findings, f, indent=4)
                print(f"Findings saved to JSON: {json_output_path}")
            except IOError as e:
                logging.error(f"Error writing to JSON file: {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred while writing JSON output: {e}")
    else:
        print("No secrets found.")

# Example usage
import math
if __name__ == "__main__":
    # Example: Scan a single file
    # python main.py config.yaml

    # Example: Scan a directory recursively
    # python main.py /path/to/config/directory -r

    # Example: Scan a directory and exclude certain files/directories
    # python main.py /path/to/config/directory -r -e "node_modules" ".git"

    # Example: Output findings to a JSON file
    # python main.py config.yaml -j output.json

    main()