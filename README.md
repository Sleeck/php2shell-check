# php2shell-check

Contrôle distant du chemin d'épuisement mémoire associé à CVE-2026-109618.
Le script envoie un GET témoin puis un seul POST multipart vers l'URL indiquée.
Ce POST peut épuiser la mémoire d'un worker PHP vulnérable : utilisez-le uniquement
sur une cible que vous êtes autorisé à tester.

## Exemple

Depuis le dossier du dépôt, avec Python 3 et sans dépendance externe :

```bash
python check_php2shell_oom.py "https://lab.example.org/index.php"
```

Remplacez l'URL d'exemple par celle du script PHP à vérifier. Pour contrôler
une règle WAF, utilisez l'URL qui passe effectivement par ce WAF.

Le résultat et le code de sortie indiquent :

- `1` : erreur d'épuisement mémoire PHP observée dans la réponse ;
- `0` : rejet du POST alors que le GET témoin passe ; confirmez son origine dans les journaux du WAF ;
- `2` : résultat indéterminé, y compris une réponse normale sans erreur mémoire.

Le test ne démontre pas une exécution de code ni l'exploitation de
CVE-2026-109619. L'absence d'erreur mémoire ne prouve pas que PHP est corrigé.
