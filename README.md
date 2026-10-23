# php2shell-check

`check_php2shell_oom.py` est une sonde distante d'épuisement mémoire multipart
inspirée d'une stratégie décrite
pour CVE-2026-109618. Une erreur mémoire ne prouve pas que cette CVE est
exploitable, ni même que la version de PHP est vulnérable.
Le script envoie un GET témoin puis un seul POST multipart vers l'URL indiquée.
Ce POST peut épuiser la mémoire d'un worker PHP, même corrigé : utilisez-le uniquement
sur une cible que vous êtes autorisé à tester.

## Exploit en laboratoire

`exploit/exploit.py` exécute la chaîne complète : fuite de la base du tas,
fuite de la base de `libphp.so`, puis exécution d'une commande système. La copie
présente ici a été vérifiée sur `php:8.4.26-apache` dans un conteneur isolé :
la commande `id` y a renvoyé `uid=33(www-data)`. Le témoin `php:8.4.27-apache`
n'a pas produit de fuite. Ce résultat dépend de la version, de la compilation
et de la configuration PHP ; il ne démontre pas l'exploitabilité d'une autre URL.

Sur un hôte Linux `amd64` avec Docker Compose et Python 3.9+ :

```bash
docker compose -f exploit/docker/docker-compose.yml up -d
python3 exploit/exploit.py -u http://127.0.0.1:8088/index.php -c 'id>/out/p1' --proof-file exploit/out/p1
docker compose -f exploit/docker/docker-compose.yml down
```

Le conteneur écoute seulement sur `127.0.0.1:8088`. Le répertoire `exploit/out`
reçoit la preuve et les offsets extraits de l'image PHP. Le script et son
environnement sont dans `exploit/` ; leur notice de licence est dans
`exploit/LICENSE`.

## Exemple

Depuis le dossier du dépôt, avec Python 3 et sans dépendance externe :

```bash
python check_php2shell_oom.py "https://lab.example.org/index.php"
```

Remplacez l'URL d'exemple par celle du script PHP à vérifier. Pour contrôler
une règle WAF, utilisez l'URL qui passe effectivement par ce WAF.

Le résultat et le code de sortie indiquent :

- `1` : erreur d'épuisement mémoire PHP observée dans la réponse, sans
  attribution possible à une CVE ;
- `0` : rejet du POST alors que le GET témoin passe ; confirmez son origine dans les journaux du WAF ;
- `2` : résultat indéterminé, y compris une réponse normale sans erreur mémoire.

Le test ne démontre ni corruption mémoire, ni exécution de code, ni exploitation
de CVE-2026-109618 ou CVE-2026-109619. L'absence d'erreur mémoire ne prouve pas
que PHP est corrigé. La sonde n'utilise pas `PHP_SESSION_UPLOAD_PROGRESS` : le
session poisoning suivi d'une inclusion de fichier local est une autre chaîne
d'exploitation, liée à l'application plutôt qu'à ces CVE du cœur de PHP.

Références : [avis PHP sur CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[avis PHP sur CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
et [manuel PHP sur la progression des uploads](https://www.php.net/manual/en/session.configuration.php).
