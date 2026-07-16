# Watchglass

> Inspect code. Keep it private.

Watchglass est une CLI open source d'audit statique et **strictement local** pour dépôts Git.
Elle détecte des secrets exposés et des configurations de sécurité courantes sans téléverser,
exécuter ou modifier les fichiers analysés.

> **Statut :** version alpha. Un rapport favorable ne garantit pas qu'un projet est sécurisé.

## Installation

Python 3.12 ou plus récent est requis.

```bash
python -m pip install .
```

Pour contribuer :

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

## Utilisation

```bash
# Rapport lisible dans le terminal
watchglass scan .

# Rapport machine et seuil adapté à la CI
watchglass scan . --format json --output report.json --fail-on high

# Rapport HTML autonome
watchglass scan ./mon-projet --format html --output watchglass.html
```

Le scanner recherche notamment les secrets et clés privées, fichiers `.env` et sensibles,
cookies faibles, CORS permissif, mode debug, défauts Dockerfile et risques GitHub Actions. Chaque
constat contient une gravité, une preuve expurgée, le fichier, la ligne et une recommandation.

## Confidentialité et sécurité

L'analyse est hors ligne par conception : Watchglass n'utilise aucune API, aucun appel réseau et
n'exécute aucun contenu du dépôt. Les fichiers trop volumineux, binaires, dépendances vendoriées,
caches et métadonnées Git sont ignorés. Le rapport peut néanmoins révéler des chemins et extraits
de configuration ; protégez-le comme un artefact de sécurité.

## Limites

Watchglass utilise des heuristiques : faux positifs et faux négatifs sont possibles. Il ne couvre
pas l'historique Git, les dépendances vulnérables, les valeurs construites à l'exécution, les
binaires, l'infrastructure distante ou la sécurité métier. Il ne réalise aucun scan offensif,
bruteforce, test réseau ou exploitation. Consultez la [spécification](docs/specification.md) et
l'[architecture](docs/architecture.md).

## Avertissement légal

Utilisez Watchglass uniquement sur des projets que vous êtes autorisé à analyser. Le logiciel est
fourni sans garantie ; ses auteurs ne sauraient être tenus responsables d'un dommage ou d'une
interprétation erronée de ses résultats.

## Licence

[MIT](LICENSE)
