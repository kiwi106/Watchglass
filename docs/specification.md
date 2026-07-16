# Spécification courte

Watchglass est une CLI Python locale qui inspecte statiquement l'arborescence d'un dépôt Git
et signale des configurations de sécurité risquées. Elle ne contacte aucun service distant, ne
modifie pas le projet analysé et n'exécute aucun de ses fichiers.

## Contrat fonctionnel

- `watchglass scan [PATH]` analyse un chemin (répertoire courant par défaut).
- Les formats `terminal`, `json` et `html` exposent les mêmes constats.
- Chaque constat fournit un identifiant stable, un titre, une gravité, une preuve expurgée, un
  chemin relatif, une ligne et une correction recommandée.
- Le code de sortie vaut `1` lorsqu'un constat atteint le seuil demandé, `0` sinon, et `2` en cas
  d'erreur d'utilisation.
- Les répertoires de métadonnées, dépendances, caches et VCS connus ne sont pas parcourus.

## Modèle `Finding`

`Finding` est une dataclass immuable : `rule_id`, `title`, `severity`, `evidence`, `path`, `line`,
`recommendation`, et `description`. `Severity` contient `info`, `low`, `medium`, `high`,
`critical`. La preuve est volontairement tronquée ou expurgée pour ne pas recopier un secret
dans les logs ou rapports.

## Threat model et limites

Watchglass vise les secrets présents en clair et les mauvaises configurations courantes dans
des fichiers texte : `.env`, clés privées, CORS, cookies, debug, Dockerfiles et workflows GitHub
Actions. L'adversaire considéré obtient le dépôt ou profite d'une application déployée avec ces
réglages.

Le scanner n'est ni un antivirus, ni un SAST complet, ni un scanner de dépendances, ni une preuve
d'absence de vulnérabilité. Il n'évalue pas les valeurs calculées à l'exécution, les secrets déjà
retirés de l'historique Git, les fichiers binaires ou les services distants. Les heuristiques
peuvent produire faux positifs et faux négatifs. Aucun scan réseau, bruteforce, exploitation,
exécution de code ou envoi de contenu n'est réalisé.
