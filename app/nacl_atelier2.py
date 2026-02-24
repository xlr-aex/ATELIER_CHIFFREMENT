"""
Atelier 2 – Chiffrement/Déchiffrement avec PyNaCl SecretBox.

SecretBox utilise l'algorithme XSalsa20-Poly1305 :
  - XSalsa20  → chiffrement par flux (stream cipher) de 256 bits
  - Poly1305  → authentification (MAC) garantissant l'intégrité

Avantages par rapport à Fernet :
  - Algorithme plus moderne (Daniel J. Bernstein)
  - Nonce explicite (24 octets) au lieu d'un IV 16 octets
  - Pas de padding nécessaire (stream cipher vs block cipher)

Usage :
    # Générer une clé (32 octets, encodée en hex) :
    python app/nacl_atelier2.py keygen

    # Exporter la clé :
    #   export NACL_SECRET_KEY='<clé_hex>'          # bash / zsh
    #   $env:NACL_SECRET_KEY='<clé_hex>'             # PowerShell

    # Chiffrer un fichier :
    python app/nacl_atelier2.py encrypt secret.txt secret.enc

    # Déchiffrer un fichier :
    python app/nacl_atelier2.py decrypt secret.enc secret.dec.txt

    # Chiffrer / déchiffrer un texte interactif :
    python app/nacl_atelier2.py text
"""

import argparse
import os
import sys
from pathlib import Path

import nacl.secret
import nacl.utils
import nacl.exceptions


# ──────────────────────────────────────────────
#  Gestion de la clé
# ──────────────────────────────────────────────

def generate_key() -> str:
    """Génère une clé aléatoire de 32 octets et la retourne en hexadécimal."""
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    return key.hex()


def get_box() -> nacl.secret.SecretBox:
    """
    Récupère la clé depuis la variable d'environnement NACL_SECRET_KEY
    (encodée en hexadécimal, 64 caractères = 32 octets) et retourne
    un objet SecretBox prêt à l'emploi.
    """
    key_hex = os.environ.get("NACL_SECRET_KEY")
    if not key_hex:
        print("❌ Variable d'environnement NACL_SECRET_KEY non définie.")
        print()
        print("   👉  Générer une clé :")
        print("      python app/nacl_atelier2.py keygen")
        print()
        print("   👉  Exporter la clé :")
        print("      export NACL_SECRET_KEY='<clé_hex>'")
        print("      $env:NACL_SECRET_KEY='<clé_hex>'")
        sys.exit(1)

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        print("❌ NACL_SECRET_KEY n'est pas un hexadécimal valide.")
        sys.exit(1)

    if len(key) != nacl.secret.SecretBox.KEY_SIZE:
        print(f"❌ La clé doit faire {nacl.secret.SecretBox.KEY_SIZE} octets "
              f"({nacl.secret.SecretBox.KEY_SIZE * 2} caractères hex). "
              f"Reçu : {len(key)} octets.")
        sys.exit(1)

    return nacl.secret.SecretBox(key)


# ──────────────────────────────────────────────
#  Chiffrement / Déchiffrement de fichiers
# ──────────────────────────────────────────────

def encrypt_file(input_path: Path, output_path: Path) -> None:
    """
    Chiffre un fichier avec SecretBox.
    Le nonce (24 octets) est généré automatiquement et
    préfixé au message chiffré par SecretBox.encrypt().
    """
    box = get_box()
    data = input_path.read_bytes()
    encrypted = box.encrypt(data)  # nonce + ciphertext + MAC
    output_path.write_bytes(encrypted)
    print(f"✅ Fichier chiffré (XSalsa20-Poly1305) : {input_path} → {output_path}")
    print(f"   Taille clair : {len(data)} octets")
    print(f"   Taille chiffré : {len(encrypted)} octets "
          f"(+{nacl.secret.SecretBox.NONCE_SIZE} nonce, +{nacl.secret.SecretBox.MACBYTES} MAC)")


def decrypt_file(input_path: Path, output_path: Path) -> None:
    """Déchiffre un fichier préalablement chiffré avec SecretBox."""
    box = get_box()
    encrypted = input_path.read_bytes()
    try:
        data = box.decrypt(encrypted)
    except nacl.exceptions.CryptoError:
        print("❌ Déchiffrement impossible : clé incorrecte ou fichier altéré.")
        sys.exit(1)
    output_path.write_bytes(data)
    print(f"✅ Fichier déchiffré : {input_path} → {output_path}")


# ──────────────────────────────────────────────
#  Mode interactif (texte)
# ──────────────────────────────────────────────

def interactive_text() -> None:
    """Chiffre puis déchiffre un texte saisi par l'utilisateur."""
    box = get_box()

    message = input("📝 Entrez le message à chiffrer : ")
    data = message.encode("utf-8")

    encrypted = box.encrypt(data)

    print("\n=== Chiffrement (XSalsa20-Poly1305) ===")
    print("Message clair    :", message)
    print("Nonce (hex)      :", encrypted.nonce.hex())
    print("Ciphertext (hex) :", encrypted.ciphertext.hex())
    print("Taille totale    :", len(encrypted), "octets")

    # Déchiffrement
    clear = box.decrypt(encrypted).decode("utf-8")
    print("\n=== Déchiffrement ===")
    print("Message déchiffré :", clear)


# ──────────────────────────────────────────────
#  Point d'entrée
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Atelier 2 – Chiffrement avec PyNaCl SecretBox (XSalsa20-Poly1305)."
    )
    sub = parser.add_subparsers(dest="mode")

    # keygen
    sub.add_parser("keygen", help="Générer une nouvelle clé secrète")

    # encrypt
    enc = sub.add_parser("encrypt", help="Chiffrer un fichier")
    enc.add_argument("input", help="Fichier d'entrée (clair)")
    enc.add_argument("output", help="Fichier de sortie (chiffré)")

    # decrypt
    dec = sub.add_parser("decrypt", help="Déchiffrer un fichier")
    dec.add_argument("input", help="Fichier d'entrée (chiffré)")
    dec.add_argument("output", help="Fichier de sortie (clair)")

    # text
    sub.add_parser("text", help="Chiffrer/déchiffrer un texte interactif")

    args = parser.parse_args()

    if args.mode is None:
        parser.print_help()
        sys.exit(0)

    if args.mode == "keygen":
        key_hex = generate_key()
        print("🔑 Clé secrète générée (hex) :")
        print(key_hex)
        print()
        print("➡️  Exportez-la :")
        print(f"   export NACL_SECRET_KEY='{key_hex}'")
        print(f"   $env:NACL_SECRET_KEY='{key_hex}'")

    elif args.mode == "text":
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
