import os
import sys
import argparse
import getpass
import shutil
import lzma
import hashlib
import tempfile

try:
    import zstandard as zstd
except ImportError:
    zstd = None

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
except ImportError:
    print("[x] pycryptodome is required for encryption. Install it with: pip install pycryptodome")
    sys.exit(1)

VERSION = "HCA v0.1 smart with encryption"
ERROR_CODES = {"INVALID_ARGS": 1, "FILE_ERROR": 2, "EXTRACTION_ERROR": 3}

MAGIC = b"HCAENC"  # Magic header for encrypted files
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256

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

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=100_000)

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return MAGIC + salt + nonce + tag + ciphertext

def decrypt_data(data: bytes, password: str) -> bytes:
    if not data.startswith(MAGIC):
        raise ValueError("Not an encrypted archive")
    offset = len(MAGIC)
    salt = data[offset:offset+SALT_SIZE]
    offset += SALT_SIZE
    nonce = data[offset:offset+NONCE_SIZE]
    offset += NONCE_SIZE
    tag = data[offset:offset+16]  # GCM tag size fixed at 16 bytes
    offset += 16
    ciphertext = data[offset:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def get_password(confirm=False):
    try:
        pwd = getpass.getpass("Enter password: ")
        if confirm:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd != pwd2:
                print("[x] Passwords do not match.")
                sys.exit(ERROR_CODES["INVALID_ARGS"])
        if not pwd:
            print("[x] Password cannot be empty.")
            sys.exit(ERROR_CODES["INVALID_ARGS"])
        return pwd
    except KeyboardInterrupt:
        print("\n[x] Interrupted during password input.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])

def compress_folder(input_folder, output_file, password=None, delete_input=False, split=False):
    print(f"[+] Compressing folder '{input_folder}' -> '{output_file}'")

    file_hashes = {}
    tmpdir = tempfile.mkdtemp()

    for full_path, rel_path in get_all_files(input_folder):
        h = hash_file(full_path)
        if h in file_hashes:
            print(f"[~] Skipping duplicate: {rel_path}")
            continue
        file_hashes[h] = rel_path
        tmp_path = os.path.join(tmpdir, rel_path)
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        shutil.copy2(full_path, tmp_path)

    tar_path = os.path.join(tmpdir, "bundle.tar")
    shutil.make_archive(tar_path[:-4], "tar", tmpdir)

    data = open(tar_path, "rb").read()
    print(f"[~] Uncompressed bundle size: {len(data)/1024:.2f} KB")

    if zstd:
        cctx = zstd.ZstdCompressor(level=22)
        compressed = cctx.compress(data)
    else:
        compressed = lzma.compress(data, preset=9)

    if password:
        encrypted = encrypt_data(compressed, password)
        with open(output_file, "wb") as f:
            f.write(encrypted)
        size_out = len(encrypted)
    else:
        with open(output_file, "wb") as f:
            f.write(compressed)
        size_out = len(compressed)

    print(f"[✓] Compressed to {size_out/1024:.2f} KB ({(size_out/len(data))*100:.1f}% of original)")

    if delete_input:
        shutil.rmtree(input_folder)
        print(f"[!] Deleted original folder: {input_folder}")

    shutil.rmtree(tmpdir)

def compress_file(input_file, output_file, password=None, delete_input=False):
    print(f"[+] Compressing file '{input_file}' -> '{output_file}'")

    with open(input_file, "rb") as f:
        data = f.read()

    print(f"[~] Uncompressed file size: {len(data)/1024:.2f} KB")

    if zstd:
        cctx = zstd.ZstdCompressor(level=22)
        compressed = cctx.compress(data)
    else:
        compressed = lzma.compress(data, preset=9)

    if password:
        encrypted = encrypt_data(compressed, password)
        with open(output_file, "wb") as f:
            f.write(encrypted)
        size_out = len(encrypted)
    else:
        with open(output_file, "wb") as f:
            f.write(compressed)
        size_out = len(compressed)

    print(f"[✓] Compressed to {size_out/1024:.2f} KB ({(size_out/len(data))*100:.1f}% of original)")

    if delete_input:
        os.remove(input_file)
        print(f"[!] Deleted original file: {input_file}")

def extract_archive(archive_file, output_folder, password=None):
    print(f"[+] Extracting '{archive_file}' -> '{output_folder}'")

    data = open(archive_file, "rb").read()
    try:
        if password:
            data = decrypt_data(data, password)
        elif data.startswith(MAGIC):
            print("[x] Archive is password protected. Use --password option.")
            sys.exit(ERROR_CODES["EXTRACTION_ERROR"])

        if zstd:
            dctx = zstd.ZstdDecompressor()
            raw = dctx.decompress(data)
        else:
            raw = lzma.decompress(data)
    except ValueError as e:
        print("[x] Decryption failed:", e)
        sys.exit(ERROR_CODES["EXTRACTION_ERROR"])
    except Exception as e:
        print("[x] Failed to decompress:", e)
        sys.exit(ERROR_CODES["EXTRACTION_ERROR"])

    tmp_tar = os.path.join(tempfile.gettempdir(), "tmp_bundle.tar")
    with open(tmp_tar, "wb") as f:
        f.write(raw)

    try:
        shutil.unpack_archive(tmp_tar, output_folder)
        print("[✓] Extraction complete (folder).")
    except (shutil.ReadError, ValueError):
        os.makedirs(output_folder, exist_ok=True)
        output_path = os.path.join(output_folder, os.path.basename(archive_file).replace(".hca",""))
        with open(output_path, "wb") as f:
            f.write(raw)
        print("[✓] Extraction complete (single file).")

def list_archive(archive_file):
    print(f"[~] Listing contents of '{archive_file}' (Compressed: {os.path.getsize(archive_file)/1024:.2f} KB)")
    print("No real file list stored in this format (yet). Just decompress to see contents.")

def print_man():
    print("""
HCA Archiver Manual
--------------------
--compress [FILE|FOLDER]     Compress the specified file or folder
--extract [ARCHIVE]          Extract the given .hca archive
--list [ARCHIVE]             Show basic info about the archive
--output, -o [PATH]          Set output file or folder
--password                  Prompt for password (encryption/decryption)
--delete                    Delete input files after compression
--version                   Show version
--man                       Show manual
--tldr                      Show summary
""")

def print_tldr():
    print("TL;DR: Use --compress FILE/FOLDER or --extract ARCHIVE. Add -o for output path.")

def main():
    parser = argparse.ArgumentParser(description="HCA Archiver")
    parser.add_argument("--compress", metavar="INPUT", help="Compress a file or folder")
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
        input_path = args.compress

        if not os.path.exists(input_path):
            print(f"[x] Input path does not exist: {input_path}")
            sys.exit(ERROR_CODES["FILE_ERROR"])

        if args.output:
            output_path = args.output
            try:
                validate_filename(os.path.basename(output_path))
            except ValueError as e:
                print(f"[x] {e}")
                sys.exit(ERROR_CODES["INVALID_ARGS"])
        else:
            base_dir = os.path.dirname(os.path.abspath(input_path))
            base_name = os.path.basename(input_path).rstrip(os.sep)
            output_path = os.path.join(base_dir, base_name + ".hca")

        password = None
        if args.password:
            password = get_password(confirm=True)

        if os.path.isdir(input_path):
            compress_folder(input_path, output_path, password, args.delete, args.split)
        elif os.path.isfile(input_path):
            compress_file(input_path, output_path, password, args.delete)
        else:
            print(f"[x] Input path is neither file nor folder: {input_path}")
            sys.exit(ERROR_CODES["INVALID_ARGS"])

    elif args.extract:
        archive_file = args.extract
        if not os.path.isfile(archive_file):
            print(f"[x] Archive file does not exist: {archive_file}")
            sys.exit(ERROR_CODES["FILE_ERROR"])

        output_folder = args.output if args.output else "extracted"
        os.makedirs(output_folder, exist_ok=True)

        password = None
        if args.password:
            # Prompt password interactively here for extraction
            password = get_password(confirm=False)

        extract_archive(archive_file, output_folder, password)

    elif args.list:
        archive_file = args.list
        if not os.path.isfile(archive_file):
            print(f"[x] Archive file does not exist: {archive_file}")
            sys.exit(ERROR_CODES["FILE_ERROR"])
        list_archive(archive_file)

    else:
        print("No operation specified. Use --help for usage.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])

if __name__ == "__main__":
    main()
