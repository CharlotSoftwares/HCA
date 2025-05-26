# Test: Compressed ≈ 609 kb to ≈ 5 kb (0.9 % of original size!) with the command "C:\> .\HCA.py --compress C:\Users\Charlot\Downloads\Test" (HCA.py was added to environment variables and was in C:\)
import os
import sys
import argparse
import getpass
import shutil
import lzma
import json
import hashlib
import tempfile

try:
    import zstandard as zstd
except ImportError:
    zstd = None

VERSION = "HCA v0.1 smart"
ERROR_CODES = {"INVALID_ARGS": 1, "FILE_ERROR": 2, "EXTRACTION_ERROR": 3}

def validate_filename(filename):
    if not filename.endswith(".hca"):
        raise ValueError("Output filename must end with .hca")

def get_all_files(folder):
    for root, dirs, files in os.walk(folder):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, folder)
            yield full_path, rel_path

def hash_file(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def compress_folder(input_folder, output_file, password=None, delete_input=False, split=False):
    print(f"[+] Compressing '{input_folder}' -> '{output_file}'")

    file_list = []
    file_hashes = {}
    tmpdir = tempfile.mkdtemp()

    # Step 1: Deduplicate and collect files
    for full_path, rel_path in get_all_files(input_folder):
        h = hash_file(full_path)
        if h in file_hashes:
            print(f"[~] Skipping duplicate: {rel_path}")
            continue
        file_hashes[h] = rel_path
        tmp_path = os.path.join(tmpdir, rel_path)
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        shutil.copy2(full_path, tmp_path)
        file_list.append((rel_path, h))

    # Step 2: Tar all into one binary blob
    tar_path = os.path.join(tmpdir, "bundle.tar")
    shutil.make_archive(tar_path[:-4], "tar", tmpdir)

    # Step 3: Compress using LZMA or Zstd
    data = open(tar_path, "rb").read()
    print(f"[~] Uncompressed bundle size: {len(data)/1024:.2f} KB")

    if zstd:
        cctx = zstd.ZstdCompressor(level=22)
        compressed = cctx.compress(data)
    else:
        compressed = lzma.compress(data, preset=9)

    with open(output_file, "wb") as f:
        f.write(compressed)

    print(f"[✓] Compressed to {len(compressed)/1024:.2f} KB ({(len(compressed)/len(data))*100:.1f}% of original)")

    if delete_input:
        shutil.rmtree(input_folder)
        print(f"[!] Deleted original folder: {input_folder}")

    shutil.rmtree(tmpdir)

def extract_archive(archive_file, output_folder, password=None):
    print(f"[+] Extracting '{archive_file}' -> '{output_folder}'")

    data = open(archive_file, "rb").read()
    try:
        if zstd:
            dctx = zstd.ZstdDecompressor()
            raw = dctx.decompress(data)
        else:
            raw = lzma.decompress(data)
    except Exception as e:
        print("[x] Failed to decompress:", e)
        sys.exit(ERROR_CODES["EXTRACTION_ERROR"])

    tmp_tar = os.path.join(tempfile.gettempdir(), "tmp_bundle.tar")
    with open(tmp_tar, "wb") as f:
        f.write(raw)

    shutil.unpack_archive(tmp_tar, output_folder)
    print("[✓] Extraction complete.")

def list_archive(archive_file):
    print(f"[~] Listing contents of '{archive_file}' (Compressed: {os.path.getsize(archive_file)/1024:.2f} KB)")
    print("No real file list stored in this format (yet). Just decompress to see contents.")

def print_man():
    print("""
HCA Archiver Manual
--------------------
--compress [FOLDER]     Compress the specified folder
--extract [ARCHIVE]     Extract the given .hca archive
--list [ARCHIVE]        Show basic info about the archive
--output, -o [PATH]     Set output path
--password              Prompt for password (currently unused)
--delete                Delete input files after compression
--version               Show version
--man                   Show full manual
--tldr                  Show summary
""")

def print_tldr():
    print("TL;DR: Use --compress FOLDER or --extract ARCHIVE. Add -o for output path.")

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
