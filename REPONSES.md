# Réponses aux questions du TP – Atelier Chiffrement

## 1. Questions de la Partie B

### Que se passe-t-il si on modifie un octet du fichier chiffré ?
Si on modifie ne serait-ce qu'un seul octet du fichier chiffré (le "token"), le déchiffrement échouera avec une erreur de type `InvalidToken`.

**Pourquoi ?**
Fernet utilise un mécanisme d'**authentification** (un HMAC - Hash-based Message Authentication Code). Avant de déchiffrer, la bibliothèque recalcule le HMAC des données et le compare à celui stocké dans le token. Si les données ont été altérées, les HMAC ne correspondent plus, et la bibliothèque refuse de traiter le fichier pour garantir son intégrité.

### Pourquoi ne faut-il pas commiter la clé dans Git ?
- **Sécurité** : Si le repo est public (ou si un attaquant accède au repo privé), il possède alors la clé et peut déchiffrer toutes les communications/données passées et futures.
- **Traçabilité** : Git conserve l'historique. Même si on supprime la clé plus tard, elle reste présente dans l'historique des commits.
- **Bonne pratique** : On sépare toujours le **code** (logique) des **secrets** (données sensibles). Les clés doivent être injectées via des variables d'environnement ou des gestionnaires de secrets (Vault, GitHub Secrets).

---

## 2. Atelier 1 : Fonctionnement avec GitHub Secrets

Le programme `app/fernet_atelier1.py` est conçu pour lire la clé depuis la variable d'environnement `FERNET_KEY`.

En production :
1. On ajoute la clé dans GitHub : `Settings` > `Secrets` > `Actions` > `New repository secret`.
2. On crée un workflow YAML (`.github/workflows/...`) qui injecte ce secret :
   ```yaml
   env:
     FERNET_KEY: ${{ secrets.FERNET_KEY }}
   ```
3. Le code Python utilise alors `os.environ.get("FERNET_KEY")` pour récupérer la valeur sans qu'elle n'apparaisse jamais en clair dans le code.
