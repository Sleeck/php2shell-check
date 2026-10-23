# php2shell-check

Sonde distante d'épuisement mémoire multipart inspirée d'une stratégie décrite
pour CVE-2026-109618. Une erreur mémoire ne prouve pas que cette CVE est
exploitable, ni même que la version de PHP est vulnérable.
Le script envoie un GET témoin puis un seul POST multipart vers l'URL indiquée.
Ce POST peut épuiser la mémoire d'un worker PHP, même corrigé : utilisez-le uniquement
sur une cible que vous êtes autorisé à tester.

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
