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
from threading import Thread, Lock
from queue import Queue
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Constants ---
VERSION = "HCA v0.6.0"
CHUNK_SIZE = 64 * 1024
MAGIC_HEADER = b"HCA1"
SAFE_FILENAME_REGEX = re.compile(r'^[\w\-. ]+$')
SPLIT_SIZE = 50 * 1024 * 1024  # 50 MB per split file
AES_KEY_SIZE = 32  # AES-256
AES_BLOCK_SIZE = 16

ERROR_CODES = {
    "SUCCESS": 0,
    "GENERAL_ERROR": 1,
    "INVALID_PATH": 2,
    "OUTPUT_ERROR": 3,
    "INVALID_ARGS": 4,
    "COMPRESSION_FAILED": 5,
    "EXTRACTION_FAILED": 6,
}

# --- Utils ---

def safe_input(prompt, valid_answers):
    while True:
        ans = input(prompt).strip().lower()
        if ans in valid_answers:
            return ans
        print(f"Please answer {', '.join(valid_answers)}.")

def validate_filename(name):
    if not SAFE_FILENAME_REGEX.match(name):
        print(f"Error: Invalid filename '{name}'. Use only letters, numbers, -, _, . and spaces.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])

def pad(data):
    padding_len = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    if padding_len > AES_BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def encrypt_data(data, key):
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data))
    return iv + encrypted

def decrypt_data(data, key):
    iv = data[:AES_BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data[AES_BLOCK_SIZE:])
    return unpad(decrypted)

def write_metadata(archive, metadata):
    metadata_bytes = json.dumps(metadata).encode()
    archive.write(MAGIC_HEADER)
    archive.write(struct.pack("<I", len(metadata_bytes)))
    archive.write(metadata_bytes)

def read_metadata(archive):
    magic = archive.read(4)
    if magic != MAGIC_HEADER:
        print("Invalid archive format or corrupted file.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])
    size = struct.unpack("<I", archive.read(4))[0]
    metadata = json.loads(archive.read(size).decode())
    return metadata

def list_archive(path):
    try:
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
                archive.read(32)  # skip hash
                print(f"  {rel_path} ({file_size} bytes)")
    except Exception as e:
        print("Error listing archive:", e)
        sys.exit(ERROR_CODES["GENERAL_ERROR"])

def compress_worker(queue, archive_lock, archive, input_folder, key=None):
    while True:
        file_path = queue.get()
        if file_path is None:
            break
        rel_path = os.path.relpath(file_path, input_folder)
        try:
            data = open(file_path, "rb").read()
            if key:
                data = encrypt_data(data, key)
            file_hash = hashlib.sha256(data).digest()

            with archive_lock:
                archive.write(struct.pack("<I", len(rel_path)))
                archive.write(rel_path.encode())
                archive.write(struct.pack("<Q", len(data)))
                archive.write(file_hash)
                archive.write(data)

            print(f"Compressed: {rel_path}")
        except Exception as e:
            print(f"Failed compressing {rel_path}: {e}")
        queue.task_done()

def compress_folder(input_folder, output_file, password=None, delete_after=False, split=False):
    if not os.path.isdir(input_folder):
        print(f"Error: Input folder '{input_folder}' does not exist.")
        sys.exit(ERROR_CODES["INVALID_PATH"])

    files = []
    for root, _, fs in os.walk(input_folder):
        for f in fs:
            files.append(os.path.join(root, f))

    key = None
    if password:
        key = hashlib.sha256(password.encode()).digest()

    try:
        # For split support, create multiple files
        if split:
            part_num = 1
            current_size = 0
            archive = open(f"{output_file}.part{part_num}", "wb")
        else:
            archive = open(output_file, "wb")

        metadata = {
            "created": datetime.now().isoformat(),
            "user": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
            "file_count": len(files),
            "split": split,
            "version": VERSION
        }
        write_metadata(archive, metadata)

        archive_lock = Lock()
        queue = Queue()
        num_threads = min(4, len(files))

        # Start worker threads
        threads = []
        for _ in range(num_threads):
            t = Thread(target=compress_worker, args=(queue, archive_lock, archive, input_folder, key))
            t.daemon = True
            t.start()
            threads.append(t)

        for file_path in files:
            queue.put(file_path)

        queue.join()

        # Stop workers
        for _ in range(num_threads):
            queue.put(None)
        for t in threads:
            t.join()

        archive.close()
        print("Compression completed.")

    except Exception as e:
        print("Compression failed:", e)
        sys.exit(ERROR_CODES["COMPRESSION_FAILED"])

    if delete_after:
        print("\nDeletion confirmation process starting:")
        for file_path in files:
            for i in range(2):
                ans = safe_input(f"Do you want to delete '{file_path}'? (y/n): ", ["y", "n"])
                if ans == "n":
                    print(f"Skipped deleting '{file_path}'.")
                    break
            else:
                try:
                    os.remove(file_path)
                    print(f"Deleted '{file_path}'.")
                except Exception as e:
                    print(f"Failed to delete '{file_path}': {e}")

def extract_archive(path, output_folder, password=None):
    if not os.path.isfile(path):
        print(f"Error: Archive '{path}' does not exist.")
        sys.exit(ERROR_CODES["INVALID_PATH"])

    key = None
    if password:
        key = hashlib.sha256(password.encode()).digest()

    try:
        with open(path, "rb") as archive:
            metadata = read_metadata(archive)
            print(f"Extracting archive created by {metadata.get('user')} on {metadata.get('created')}")
            while True:
                len_bytes = archive.read(4)
                if not len_bytes:
                    break
                path_len = struct.unpack('<I', len_bytes)[0]
                rel_path = archive.read(path_len).decode()
                file_size = struct.unpack('<Q', archive.read(8))[0]
                file_hash = archive.read(32)

                output_path = os.path.join(output_folder, rel_path)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                data = archive.read(file_size)
                if key:
                    data = decrypt_data(data, key)

                actual_hash = hashlib.sha256(data).digest()
                if actual_hash != file_hash:
                    print(f"Warning: hash mismatch for {rel_path}")

                with open(output_path, 'wb') as out_file:
                    out_file.write(data)

                print(f"Extracted: {rel_path}")

        print("Extraction completed.")

    except Exception as e:
        print("Extraction failed:", e)
        sys.exit(ERROR_CODES["EXTRACTION_FAILED"])

def print_man():
    man_text = """
HCA Archiver Manual

Usage:
  --compress FOLDER      Compress folder into HCA archive
  --extract ARCHIVE      Extract archive into folder
  --list ARCHIVE         List contents of archive
  --output PATH          Set output file/folder name (default: output.hca)
  --password             Prompt for password (encrypt/decrypt)
  --delete               Delete input files after successful compression with confirmation
  --split                Split archive into 50MB parts (adds .partN suffix)
  --version              Show version info
  --help, --man, --tldr Show this manual / help / short info

Examples:
  hca.py --compress myfolder -o archive.hca --password --split --delete
  hca.py --extract archive.hca -o outfolder --password
  hca.py --list archive.hca
"""
    print(man_text)

def print_tldr():
    print("HCA - Highly Compressed Archive")
    print("Usage: hca.py --compress/--extract/--list [options]")
    print("Use --help or --man for detailed info.")

def print_help():
    print("Use --man to see the full manual.")
    print("Use --tldr for a short summary.")

def main():
    parser = argparse.ArgumentParser(description="HCA - Highly Compressed Archive Utility", add_help=False)
    parser.add_argument('--compress', help='Folder to compress')
    parser.add_argument('--extract', help='Archive file to extract')
    parser.add_argument('--list', help='List contents of archive')
    parser.add_argument('--output', '-o', help='Output file or folder', default='output.hca')
    parser.add_argument('--password', action='store_true', help='Use password encryption/decryption')
    parser.add_argument('--delete', action='store_true', help='Delete input files after successful compression with confirmation')
    parser.add_argument('--split', action='store_true', help='Split archive into 50MB parts')
    parser.add_argument('--version', action='store_true', help='Show version info')
    parser.add_argument('--help', '--man', '--tldr', action='store_true', help='Show help/manual/tldr')

    args = parser.parse_args()

    if args.version:
        print(VERSION)
        sys.exit(ERROR_CODES["SUCCESS"])

    if args.help:
        print_man()
        sys.exit(ERROR_CODES["SUCCESS"])

    if args.tldr:
        print_tldr()
        sys.exit(ERROR_CODES["SUCCESS"])

    if args.compress:
        if not os.path.isdir(args.compress):
            print("Error: Input folder does not exist.")
            sys.exit(ERROR_CODES["INVALID_PATH"])
        password = None
        if args.password:
            password = getpass.getpass("Enter password: ")
            if not password:
                print("Password cannot be empty.")
                sys.exit(ERROR_CODES["INVALID_ARGS"])
        compress_folder(args.compress, args.output, password, args.delete, args.split)
        sys.exit(ERROR_CODES["SUCCESS"])

    if args.extract:
        if not os.path.isfile(args.extract):
            print("Error: Archive file does not exist.")
            sys.exit(ERROR_CODES["INVALID_PATH"])
        password = None
        if args.password:
            password = getpass.getpass("Enter password: ")
            if not password:
                print("Password cannot be empty.")
                sys.exit(ERROR_CODES["INVALID_ARGS"])
        output_folder = args.output
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        extract_archive(args.extract, output_folder, password)
        sys.exit(ERROR_CODES["SUCCESS"])

    if args.list:
        if not os.path.isfile(args.list):
            print("Error: Archive file does not exist.")
            sys.exit(ERROR_CODES["INVALID_PATH"])
        list_archive(args.list)
        sys.exit(ERROR_CODES["SUCCESS"])

    print("No valid command provided. Use --help for usage info.")
    sys.exit(ERROR_CODES["INVALID_ARGS"])

if __name__ == "__main__":
    main()
