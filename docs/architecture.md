# Architecture

```text
src/watchglass/
|-- cli/          # interface Typer et codes de sortie
|-- core/         # découverte de fichiers et orchestration
|-- checks/       # règles indépendantes d'analyse statique
|-- reporters/    # terminal, JSON et HTML/Jinja2
`-- models/       # Finding et Severity
tests/
|-- fixtures/
|   |-- vulnerable_project/
|   `-- secure_project/
`-- test_*.py
docs/
|-- architecture.md
`-- specification.md
```

Une règle reçoit un fichier découvert et renvoie zéro ou plusieurs `Finding`. L'orchestrateur
normalise les chemins, isole les erreurs de lecture et trie les résultats. Les reporters ne
refont aucune analyse et n'exposent que le modèle normalisé.
