"""Valida el PR de Forgejo y todos sus commits antes de permitir integracion."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request


def check_pr(pr, issue, subjects):
    match = re.fullmatch(r"(feature|bugfix|chore)/(\d+)-[a-z0-9]+(?:-[a-z0-9]+)*", pr["head"]["ref"])
    if not match:
        raise ValueError("La rama debe usar <feature|bugfix|chore>/<issue>-slug.")
    kind, number = match.groups()
    if pr["base"]["ref"] != "develop":
        raise ValueError("Las ramas de trabajo deben apuntar a develop.")
    if not re.search(rf"\b(?:Closes|Fixes|Resolves)\s+#{number}(?!\d)\b", pr.get("body") or "", re.I):
        raise ValueError(f"El cuerpo debe incluir Closes #{number}.")
    expected_label = "type::" + {"feature": "feature", "bugfix": "bug", "chore": "chore"}[kind]
    for obj in (pr, issue):
        labels = [label["name"] for label in obj.get("labels", []) if label["name"].startswith("type::")]
        if labels != [expected_label]:
            raise ValueError(f"Issue y PR deben tener solo la etiqueta de tipo {expected_label}.")
    if not issue.get("milestone") or not pr.get("milestone") or issue["milestone"]["id"] != pr["milestone"]["id"]:
        raise ValueError("Issue y PR deben compartir un milestone.")
    if issue.get("state") != "open":
        raise ValueError("El issue debe estar abierto durante la revision.")
    if not subjects:
        raise ValueError("No hay commits nuevos para validar.")
    for subject in subjects:
        if not 10 <= len(subject) <= 72 or re.fullmatch(
            r"(?:wip|todo|test|prueba|pruebas|cambios|arreglos|update|fix|fixes|minor|varios|\.+)", subject.strip(), re.I
        ):
            raise ValueError(f"Asunto de commit invalido: {subject!r}")


def main():
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        print("La validacion de metadatos aplica al pull request hacia develop.")
        return
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event["pull_request"]
    branch = pr["head"]["ref"]
    match = re.match(r"(?:feature|bugfix|chore)/(\d+)-", branch)
    if not match:
        raise ValueError("Nombre de rama invalido.")
    api = os.environ["GITHUB_SERVER_URL"].rstrip("/") + "/api/v1/repos/" + os.environ["GITHUB_REPOSITORY"]
    headers = {"Authorization": "token " + os.environ["GITHUB_TOKEN"], "Accept": "application/json"}
    # Leer metadatos actuales permite relanzar CI tras editar etiquetas o milestone.
    def get(path):
        request = urllib.request.Request(api + path, headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    current = get(f"/pulls/{pr['number']}")
    if current["head"]["sha"] != pr["head"]["sha"]:
        raise ValueError("La rama cambio durante la ejecucion; validar el HEAD mas reciente.")
    issue = get(f"/issues/{match.group(1)}")
    if "pull_request" in issue:
        raise ValueError("La referencia debe apuntar a un issue, no a otro PR.")
    subjects = subprocess.check_output(
        ["git", "log", "--format=%s", f"{pr['base']['sha']}..{pr['head']['sha']}"], text=True
    ).splitlines()
    check_pr(current, issue, subjects)
    print(f"Gitflow valido: {branch} -> develop; issue #{match.group(1)}; {len(subjects)} commit(s).")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
