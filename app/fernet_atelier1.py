"""
Atelier 1 – Chiffrement/Déchiffrement Fernet avec clé stockée
dans un Repository Secret GitHub (variable d'environnement FERNET_KEY).

Usage :
    # Définir la clé (stockée dans un GitHub Secret puis injectée via env) :
    #   export FERNET_KEY='<votre_clé_fernet>'       # Linux / macOS
    #   $env:FERNET_KEY='<votre_clé_fernet>'          # PowerShell

    # Chiffrer un fichier :
    python app/fernet_atelier1.py encrypt secret.txt secret.enc

    # Déchiffrer un fichier :
    python app/fernet_atelier1.py decrypt secret.enc secret.dec.txt

    # Chiffrer / déchiffrer un texte interactif :
    python app/fernet_atelier1.py text
"""

import argparse
import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


# ──────────────────────────────────────────────
#  Gestion de la clé via variable d'environnement
# ──────────────────────────────────────────────

def get_key() -> bytes:
    """
    Récupère la clé Fernet depuis la variable d'environnement FERNET_KEY.
    En production cette variable est alimentée par un GitHub Repository Secret
    (Settings → Secrets and variables → Actions → New repository secret).
    """
    key = os.environ.get("FERNET_KEY")
    if not key:
        print("❌ Variable d'environnement FERNET_KEY non définie.")
        print()
        print("   👉  Pour générer une clé :")
        print('      python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"')
        print()
        print("   👉  Puis l'exporter :")
        print("      export FERNET_KEY='<clé>'        # bash / zsh")
        print("      $env:FERNET_KEY='<clé>'           # PowerShell")
        print()
        print("   👉  Pour GitHub Actions, ajoutez la clé dans :")
        print("      Settings → Secrets and variables → Actions → New repository secret")
        print("      Nom : FERNET_KEY    Valeur : <clé>")
        sys.exit(1)
    return key.encode()


def get_fernet() -> Fernet:
    """Retourne un objet Fernet initialisé avec la clé d'environnement."""
    return Fernet(get_key())


# ──────────────────────────────────────────────
#  Chiffrement / Déchiffrement de fichiers
# ──────────────────────────────────────────────

def encrypt_file(input_path: Path, output_path: Path) -> None:
    """Chiffre le contenu d'un fichier et écrit le token dans output_path."""
    f = get_fernet()
    data = input_path.read_bytes()
    token = f.encrypt(data)
    output_path.write_bytes(token)
    print(f"✅ Fichier chiffré : {input_path} → {output_path}")


def decrypt_file(input_path: Path, output_path: Path) -> None:
    """Déchiffre un token Fernet contenu dans un fichier."""
    f = get_fernet()
    token = input_path.read_bytes()
    try:
        data = f.decrypt(token)
    except InvalidToken:
        print("❌ Déchiffrement impossible : clé incorrecte ou fichier altéré.")
        sys.exit(1)
    output_path.write_bytes(data)
    print(f"✅ Fichier déchiffré : {input_path} → {output_path}")


# ──────────────────────────────────────────────
#  Mode interactif (texte)
# ──────────────────────────────────────────────

def interactive_text() -> None:
    """Chiffre puis déchiffre un texte saisi par l'utilisateur."""
    f = get_fernet()

    message = input("📝 Entrez le message à chiffrer : ")
    token = f.encrypt(message.encode("utf-8"))

    print("\n=== Chiffrement ===")
    print("Message clair   :", message)
    print("Token chiffré   :", token.decode("utf-8"))

    clear = f.decrypt(token).decode("utf-8")
    print("\n=== Déchiffrement ===")
    print("Message déchiffré :", clear)


# ──────────────────────────────────────────────
#  Point d'entrée
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Atelier 1 – Chiffrement Fernet avec clé GitHub Secret (env FERNET_KEY)."
    )
    sub = parser.add_subparsers(dest="mode")

    # Sous-commande encrypt
    enc = sub.add_parser("encrypt", help="Chiffrer un fichier")
    enc.add_argument("input", help="Fichier d'entrée (clair)")
    enc.add_argument("output", help="Fichier de sortie (chiffré)")

    # Sous-commande decrypt
    dec = sub.add_parser("decrypt", help="Déchiffrer un fichier")
    dec.add_argument("input", help="Fichier d'entrée (chiffré)")
    dec.add_argument("output", help="Fichier de sortie (clair)")

    # Sous-commande text
    sub.add_parser("text", help="Chiffrer/déchiffrer un texte interactif")

    args = parser.parse_args()

    if args.mode is None:
        parser.print_help()
        sys.exit(0)

    if args.mode == "text":
        interactive_text()
    else:
        in_path = Path(args.input)
        out_path = Path(args.output)
        if not in_path.exists():
            print(f"❌ Fichier introuvable : {in_path}")
            sys.exit(1)
        if args.mode == "encrypt":
            encrypt_file(in_path, out_path)
        else:
            decrypt_file(in_path, out_path)


if __name__ == "__main__":
    main()
