import argparse
import json
import lzma
import os
import re
import struct
import sys
import time
import hashlib
import getpass
from datetime import datetime

# Constants
VERSION = "HCA v0.4.0"
CHUNK_SIZE = 64 * 1024
SAFE_FILENAME_REGEX = re.compile(r'^[\w\-. ]+$')
MAGIC_HEADER = b"HCA1"

ERROR_CODES = {
    "SUCCESS": 0,
    "GENERAL_ERROR": 1,
    "INVALID_PATH": 2,
    "OUTPUT_ERROR": 3,
    "INVALID_ARGS": 4,
    "FILTERS_ERROR": 5,
    "COMPRESSION_FAILED": 6,
    "EXTRACTION_FAILED": 7,
}

# Load filters (future feature)
def load_filters(filename='filters.json'):
    if not os.path.exists(filename):
        return {"compressed_extensions": []}
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception:
        return {"compressed_extensions": []}

# Validate output filename
def validate_filename(name):
    if not SAFE_FILENAME_REGEX.match(name):
        print(f"Error: Invalid filename '{name}'")
        sys.exit(ERROR_CODES["INVALID_ARGS"])

# Write metadata and magic header
def write_metadata(archive, metadata):
    metadata_bytes = json.dumps(metadata).encode()
    archive.write(MAGIC_HEADER)
    archive.write(struct.pack("<I", len(metadata_bytes)))
    archive.write(metadata_bytes)

# Read metadata
def read_metadata(archive):
    magic = archive.read(4)
    if magic != MAGIC_HEADER:
        print("Invalid archive format.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])
    size = struct.unpack("<I", archive.read(4))[0]
    metadata = json.loads(archive.read(size).decode())
    return metadata

# List archive contents
def list_archive(path):
    with open(path, "rb") as archive:
        metadata = read_metadata(archive)
        print("Archive Metadata:")
        for k, v in metadata.items():
            print(f"  {k}: {v}")

        print("\nContents:")
        while True:
            len_bytes = archive.read(4)
            if not len_bytes:
                break
            path_len = struct.unpack('<I', len_bytes)[0]
            rel_path = archive.read(path_len).decode()
            file_size = struct.unpack('<Q', archive.read(8))[0]
            archive.read(64)  # Skip hash
            print(f"  {rel_path} ({file_size} bytes)")

# Compress folder
def compress_folder(input_folder, output_file, password=None):
    filters = load_filters()
    files = []
    for root, _, fs in os.walk(input_folder):
        for f in fs:
            files.append(os.path.join(root, f))

    try:
        with open(output_file, "wb") as archive:
            metadata = {
                "created": datetime.now().isoformat(),
                "user": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
                "file_count": len(files)
            }
            write_metadata(archive, metadata)

            compressor = lzma.LZMACompressor()
            for file_path in files:
                rel_path = os.path.relpath(file_path, input_folder)
                data = open(file_path, "rb").read()
                file_hash = hashlib.sha256(data).hexdigest().encode()
                archive.write(struct.pack("<I", len(rel_path)))
                archive.write(rel_path.encode())
                archive.write(struct.pack("<Q", len(data)))
                archive.write(file_hash)
                archive.write(compressor.compress(data))
            archive.write(compressor.flush())

    except Exception as e:
        print("Compression failed:", e)
        sys.exit(ERROR_CODES["COMPRESSION_FAILED"])

# Extract archive
def extract_archive(path, output_folder):
    try:
        with open(path, "rb") as archive:
            metadata = read_metadata(archive)
            print("Extracting archive created by", metadata.get("user"), "on", metadata.get("created"))
            decompressor = lzma.LZMADecompressor()

            while True:
                len_bytes = archive.read(4)
                if not len_bytes:
                    break
                path_len = struct.unpack('<I', len_bytes)[0]
                rel_path = archive.read(path_len).decode()
                file_size = struct.unpack('<Q', archive.read(8))[0]
                file_hash = archive.read(64)

                output_path = os.path.join(output_folder, rel_path)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                with open(output_path, 'wb') as out_file:
                    remaining = file_size
                    hasher = hashlib.sha256()
                    while remaining > 0:
                        chunk = archive.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            break
                        data = decompressor.decompress(chunk)
                        out_file.write(data)
                        hasher.update(data)
                        remaining -= len(data)

                    if hasher.hexdigest().encode() != file_hash:
                        print(f"Warning: hash mismatch for {rel_path}")
    except Exception as e:
        print("Extraction failed:", e)
        sys.exit(ERROR_CODES["EXTRACTION_FAILED"])

# CLI entry point
def main():
    parser = argparse.ArgumentParser(description="HCA Archiver - Highly Compressed Archive")
    parser.add_argument("--compress", metavar="FOLDER", help="Compress folder into .hca archive")
    parser.add_argument("--extract", metavar="ARCHIVE", help="Extract .hca archive")
    parser.add_argument("--output", "-o", default="output.hca", help="Output file or directory")
    parser.add_argument("--password", action="store_true", help="Prompt for password (not yet implemented)")
    parser.add_argument("--list", metavar="ARCHIVE", help="List contents of archive")
    parser.add_argument("--version", action="store_true", help="Show version info")

    args = parser.parse_args()

    if args.version:
        print(VERSION)
        sys.exit(0)

    if args.list:
        list_archive(args.list)
        sys.exit(0)

    if args.compress:
        validate_filename(args.output)
        pwd = getpass.getpass("Enter password: ") if args.password else None
        compress_folder(args.compress, args.output, pwd)
        print("Compression completed.")
        sys.exit(0)

    if args.extract:
        extract_archive(args.extract, args.output)
        print("Extraction completed.")
        sys.exit(0)

    parser.print_help()

if __name__ == "__main__":
    main()
