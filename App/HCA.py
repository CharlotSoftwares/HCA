import argparse
import json
import os
import re
import struct
import sys
import hashlib
import getpass
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Constants ---
VERSION = "HCA v0.6.0"
MAGIC_HEADER = b"HCA1"
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
SAFE_FILENAME_REGEX = re.compile(r'^[\w\-. ]+$')

# --- Utility functions ---

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
    padding_len = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    if padding_len < 1 or padding_len > AES_BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding bytes")
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
    metadata_bytes = json.dumps(metadata).encode('utf-8')
    archive.write(MAGIC_HEADER)
    archive.write(struct.pack("<I", len(metadata_bytes)))
    archive.write(metadata_bytes)

def read_metadata(archive):
    magic = archive.read(4)
    if magic != MAGIC_HEADER:
        print("Invalid archive format or corrupted file.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])
    size_bytes = archive.read(4)
    if len(size_bytes) < 4:
        print("Invalid archive format or corrupted file (metadata size).")
        sys.exit(ERROR_CODES["INVALID_ARGS"])
    size = struct.unpack("<I", size_bytes)[0]
    metadata_bytes = archive.read(size)
    if len(metadata_bytes) < size:
        print("Invalid archive format or corrupted file (metadata content).")
        sys.exit(ERROR_CODES["INVALID_ARGS"])
    metadata = json.loads(metadata_bytes.decode('utf-8'))
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
                if not len_bytes or len(len_bytes) < 4:
                    break
                path_len = struct.unpack('<I', len_bytes)[0]
                rel_path_bytes = archive.read(path_len)
                if len(rel_path_bytes) < path_len:
                    break
                rel_path = rel_path_bytes.decode('utf-8')
                file_size_bytes = archive.read(8)
                if len(file_size_bytes) < 8:
                    break
                file_size = struct.unpack('<Q', file_size_bytes)[0]
                file_hash = archive.read(32)
                if len(file_hash) < 32:
                    break
                print(f"  {rel_path} ({file_size} bytes)")
                archive.seek(file_size, os.SEEK_CUR)
    except Exception as e:
        print("Error listing archive:", e)
        sys.exit(ERROR_CODES["GENERAL_ERROR"])

def compress_worker(queue, archive_lock, archive, input_folder, key=None):
    while True:
        file_path = queue.get()
        if file_path is None:
            queue.task_done()
            break
        rel_path = os.path.relpath(file_path, input_folder)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            if key:
                data = encrypt_data(data, key)
            file_hash = hashlib.sha256(data).digest()

            with archive_lock:
                archive.write(struct.pack("<I", len(rel_path.encode('utf-8'))))
                archive.write(rel_path.encode('utf-8'))
                archive.write(struct.pack("<Q", len(data)))
                archive.write(file_hash)
                archive.write(data)

            print(f"Compressed: {rel_path}")
        except Exception as e:
            print(f"Failed compressing {rel_path}: {e}")
        finally:
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
        key = hashlib.sha256(password.encode('utf-8')).digest()

    try:
        archive_lock = Lock()
        queue = Queue()
        num_threads = min(4, len(files)) if files else 1

        if split:
            # Implementing split files would require more complex handling,
            # for now raise NotImplementedError or simply warn
            print("Split archive feature is not implemented yet.")
            sys.exit(ERROR_CODES["INVALID_ARGS"])
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
            for _ in range(2):
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
        key = hashlib.sha256(password.encode('utf-8')).digest()

    try:
        with open(path, "rb") as archive:
            metadata = read_metadata(archive)
            print(f"Extracting archive created by {metadata.get('user')} on {metadata.get('created')}")
            while True:
                len_bytes = archive.read(4)
                if not len_bytes or len(len_bytes) < 4:
                    break
                path_len = struct.unpack('<I', len_bytes)[0]
                rel_path_bytes = archive.read(path_len)
                if len(rel_path_bytes) < path_len:
                    print("Archive corrupted or incomplete.")
                    sys.exit(ERROR_CODES["EXTRACTION_FAILED"])
                rel_path = rel_path_bytes.decode('utf-8')
                file_size_bytes = archive.read(8)
                if len(file_size_bytes) < 8:
                    print("Archive corrupted or incomplete.")
                    sys.exit(ERROR_CODES["EXTRACTION_FAILED"])
                file_size = struct.unpack('<Q', file_size_bytes)[0]
                file_hash = archive.read(32)
                if len(file_hash) < 32:
                    print("Archive corrupted or incomplete.")
                    sys.exit(ERROR_CODES["EXTRACTION_FAILED"])

                output_path = os.path.join(output_folder, rel_path)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                data = archive.read(file_size)
                if len(data) < file_size:
                    print("Archive corrupted or incomplete.")
                    sys.exit(ERROR_CODES["EXTRACTION_FAILED"])

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
  --split                Split archive into 50MB parts (adds .partN suffix) [Not implemented]
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
    parser = argparse.ArgumentParser(description="HCA Archiver")
    parser.add_argument("--compress", metavar="FOLDER", help="Compress a folder")
    parser.add_argument("--extract", metavar="ARCHIVE", help="Extract an archive")
    parser.add_argument("--list", metavar="ARCHIVE", help="List contents of an archive")
    parser.add_argument("--output", "-o", metavar="PATH", help="Output file or folder")
    parser.add_argument("--password", action="store_true", help="Use password for encryption/decryption")
    parser.add_argument("--delete", action="store_true", help="Delete input files after compression")
    parser.add_argument("--split", action="store_true", help="Split archive into parts (Not implemented)")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--man", action="store_true", help="Show manual")
    parser.add_argument("--tldr", action="store_true", help="Show summary")


    args = parser.parse_args()

    if args.version:
        print(VERSION)
        sys.exit(0)

    if args.man:
        print_man()
        sys.exit(0)

    if args.tldr:
        print_tldr()
        sys.exit(0)

    if args.compress:
        input_folder = args.compress
        output_file = args.output if args.output else "output.hca"
        validate_filename(os.path.basename(output_file))
        password = None
        if args.password:
            password = getpass.getpass("Enter password: ")
        compress_folder(input_folder, output_file, password, args.delete, args.split)

    elif args.extract:
        archive_file = args.extract
        output_folder = args.output if args.output else "extracted"
        os.makedirs(output_folder, exist_ok=True)
        password = None
        if args.password:
            password = getpass.getpass("Enter password: ")
        extract_archive(archive_file, output_folder, password)

    elif args.list:
        archive_file = args.list
        list_archive(archive_file)

    else:
        print("No operation specified. Use --help for usage.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])

if __name__ == "__main__":
    main()
