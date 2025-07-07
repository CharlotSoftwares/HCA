VERSION = "HCA v0.1 intelligent avec chiffrement"
ERROR_CODES = {"INVALID_ARGS": 1, "FILE_ERROR": 2, "EXTRACTION_ERROR": 3}

MAGIC = b"HCAENC"  # En-tête magique pour les fichiers chiffrés

...

def validate_filename(filename):
    if not filename.endswith(".hca"):
        raise ValueError("Le nom du fichier de sortie doit se terminer par .hca")

...

def get_password(confirm=False):
    try:
        pwd = getpass.getpass("Entrez le mot de passe : ")
        if confirm:
            pwd2 = getpass.getpass("Confirmez le mot de passe : ")
            if pwd != pwd2:
                print("[x] Les mots de passe ne correspondent pas.")
                sys.exit(ERROR_CODES["INVALID_ARGS"])
        if not pwd:
            print("[x] Le mot de passe ne peut pas être vide.")
            sys.exit(ERROR_CODES["INVALID_ARGS"])
        return pwd
    except KeyboardInterrupt:
        print("\n[x] Saisie du mot de passe interrompue.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])

def compress_folder(input_folder, output_file, password=None, delete_input=False, split=False):
    print(f"[+] Compression du dossier '{input_folder}' -> '{output_file}'")

    ...

    print(f"[~] Taille du paquet non compressé : {len(data)/1024:.2f} Ko")

    ...

    print(f"[✓] Comprimé à {size_out/1024:.2f} Ko ({(size_out/len(data))*100:.1f}% de l'original)")

    if delete_input:
        shutil.rmtree(input_folder)
        print(f"[!] Dossier original supprimé : {input_folder}")

...

def compress_file(input_file, output_file, password=None, delete_input=False):
    print(f"[+] Compression du fichier '{input_file}' -> '{output_file}'")

    ...

    print(f"[~] Taille du fichier non compressé : {len(data)/1024:.2f} Ko")

    ...

    print(f"[✓] Comprimé à {size_out/1024:.2f} Ko ({(size_out/len(data))*100:.1f}% de l'original)")

    if delete_input:
        os.remove(input_file)
        print(f"[!] Fichier original supprimé : {input_file}")

...

def extract_archive(archive_file, output_folder, password=None):
    print(f"[+] Extraction de '{archive_file}' -> '{output_folder}'")

    ...

            print("[x] L’archive est protégée par mot de passe. Utilisez l’option --password.")
            sys.exit(ERROR_CODES["EXTRACTION_ERROR"])

    ...

        print("[x] Échec de la décompression :", e)
        sys.exit(ERROR_CODES["EXTRACTION_ERROR"])

    ...

        print("[✓] Extraction terminée (dossier).")
    except (shutil.ReadError, ValueError):
        ...
        print("[✓] Extraction terminée (fichier unique).")

def list_archive(archive_file):
    print(f"[~] Affichage du contenu de '{archive_file}' (Taille compressée : {os.path.getsize(archive_file)/1024:.2f} Ko)")
    print("Aucune vraie liste de fichiers enregistrée dans ce format (pour l’instant). Décompressez pour voir le contenu.")

def print_man():
    print("""
Manuel de l'archiviste HCA
---------------------------
--compress [FICHIER|DOSSIER]   Compresse le fichier ou dossier spécifié
--extract [ARCHIVE]            Extrait l’archive .hca donnée
--list [ARCHIVE]               Affiche les informations de base de l’archive
--output, -o [CHEMIN]          Définit le fichier ou dossier de sortie
--password                     Demande un mot de passe (chiffrement/déchiffrement)
--delete                       Supprime les fichiers originaux après compression
--version                      Affiche la version
--man                          Affiche le manuel
--tldr                         Affiche le résumé
""")

def print_tldr():
    print("TL;DR : Utilisez --compress FICHIER/DOSSIER ou --extract ARCHIVE. Ajoutez -o pour définir le chemin de sortie.")

...

    if args.compress:
        ...

        if not os.path.exists(input_path):
            print(f"[x] Le chemin d’entrée n’existe pas : {input_path}")
            sys.exit(ERROR_CODES["FILE_ERROR"])

        ...

        password = None
        if args.password:
            password = get_password(confirm=True)

        ...

            print(f"[x] Le chemin d’entrée n’est ni un fichier ni un dossier : {input_path}")
            sys.exit(ERROR_CODES["INVALID_ARGS"])

    elif args.extract:
        ...
        if not os.path.isfile(archive_file):
            print(f"[x] Le fichier archive n’existe pas : {archive_file}")
            sys.exit(ERROR_CODES["FILE_ERROR"])

        ...

            password = get_password(confirm=False)

        extract_archive(archive_file, output_folder, password)

    elif args.list:
        ...
        if not os.path.isfile(archive_file):
            print(f"[x] Le fichier archive n’existe pas : {archive_file}")
            sys.exit(ERROR_CODES["FILE_ERROR"])
        list_archive(archive_file)

    else:
        print("Aucune opération spécifiée. Utilisez --help pour l’aide.")
        sys.exit(ERROR_CODES["INVALID_ARGS"])
