# DECISIONS — Document Security Scanner

Ce fichier trace les décisions d'architecture prises au fil des phases (brief en 18 phases).
Statut : vivant — on ajoute une entrée à chaque décision structurante.

## Référentiel

- **Brief :** plateforme SaaS d'analyse/sanitisation de documents (upload, fast scan, static + YARA,
  sandbox dynamique, IA, risque, CDR) pour ~5 000 docs/mois.
- Cycle de vie d'un scan : `QUEUED → PROCESSING → COMPLETED | FAILED`.
- Schéma `Finding` obligatoire (§2.2) : `type / value / source / severity / confidence / evidence /
  timestamp / location / tags / analyzer_version`.
- L'**IA (LLM) n'est jamais un contrôle de sécurité** (jamais en verdict/action).
- Séparer **risque** (quantitatif) / **verdict** / **action** (décisions de politique).
- Sandbox = **gate dur** (pas de bypass).
- Pas de Celery/Redis prématuré (§2.5) : worker thread + file DB au MVP.

## M1 — Socle + async

### D-01 : Files d'attente — worker thread + DB (`FOR UPDATE SKIP LOCKED`)
`workers/processor.py` utilise un pool de threads (N `scan-worker`) qui pollent la DB et réclament
des scans `QUEUED` via `FOR UPDATE SKIP LOCKED` (`db/repositories/scans.py::claim_next_queued`).
- **Pourquoi :** conforme §2.5 (pas de Celery/Redis au MVP), simple, aucun infra supplémentaire, convient
  au volume (~5 000/mois).
- **Limites assumées :** non durable (jobs perdus si le process meurt), non horizontale. Si ces besoins
  apparaissent → migrer vers Celery + Redis. Documenté dans le code.
- **Statut :** utilisé de M1 à M5 ; **remplacé en M6 par une file Redis Streams** (voir D-14).

### D-02 : Seuils de risque — provisoires et configurables (§8)
- `risk_safe_max = 0` (risque `<= 0` → `SAFE/ALLOW`)
- `risk_suspect_max = 40` (inutilisé directement dans le mapping actuel, réservé)
- `risk_malicious_min = 75` (`>= 75` → `MALICIOUS/REJECT`) ; sinon → `SUSPICIOUS/QUARANTINE`.
Valeurs **provisoires**, à confirmer/calibrer par le client. Centralisées dans `core/config.py` +
variables d'environnement. Le chemin `risque → verdict → action` est isolé dans
`orchestrator/scanner.py::_decide` pour faciliter ce calibrage.

### D-03 : Stockage — répertoires séparés par rôle
`storage/uploads`, `storage/quarantine`, `storage/sanitized`, `storage/reports` sont distincts
(`core/config.py` + `core/security.py`). Fichiers analysés **content-adressés** `{sha256}.bin`.
Séparation stricte des zones de confiance (notamment uploads non fiables vs outputs sanitized fiables).

### D-04 : Un analyseur ne doit jamais faire échouer le scan
L'orchestrateur `run_pipeline` englobe chaque appel d'analyseur dans un `try/except` : une erreur d'un
analyseur est capturée en `AnalysisResult.status = ERROR` et transformée en finding, sans tuer le job.

### D-05 : Enums stockés par valeur (SQLAlchemy `values_callable`)
Les enums DB (`ScanStatus`, `Verdict`, `Action`, `Severity`, ...) sont persistés par leur **valeur**
(`values_callable=lambda values: [e.value for e in values]`), pas par leur nom Python, pour stabilité
du schéma. Un bug initial (factory renvoyant une lambda au lieu d'une fonction directe) a été corrigé.

### D-06 : Reset dev — `DROP SCHEMA public CASCADE`
`backend/scripts/reset_db.py` détruit/recrée le schéma (utile car le refactor M1 change les types/enums).
Uniquement en dev. Le script ajoute `backend/` au `sys.path` pour être lançable depuis `scripts/`.

## M3 — Dynamic Sandbox Analysis

### D-07 : Exécution depuis le bind mount ro (pas de tmpfs noexec)
Docker Desktop force `noexec` sur tous les `tmpfs`, donc copier l'échantillon dans `/exec` ou `/tmp`
pour l'exécuter est impossible. L'échantillon est exécuté **directement depuis le bind mount
read-only `/analysis/input`** (exécutable en 9p/drvfs). Les scripts `#!` sont lancés via leur
interpréteur (`/bin/sh`, `/usr/local/bin/python3`, ...) ; les binaires via `execve`. Le rootfs reste
`ro` : rien ne peut être écrit sur l'entrée.

### D-08 : Le sandbox ne produit que de l'evidence (jamais un verdict)
Conformément à la séparation risque/verdict/action (D-02), le sandbox émet des findings
`source=sandbox` (type/severity/confidence/evidence) mais **ne décide jamais** `SAFE/SUSPICIOUS/
MALICIOUS`. Le risque est agrégé par `orchestrator/scanner.py` (poids sévérité × confiance) et le
verdict/action dérivés par `_decide`. Un bénin qui "se comporte normalement" n'ajoute donc pas de
risque sandbox (testé : PDF bénin → `risk=0, SAFE`).

### D-09 : Statuts distincts + filtrage du bruit d'infrastructure
- Statuts terminaux distincts : `completed/timeout/crashed/failed_to_start/resource_limit` (les
  échecs ne sont pas réduits à `FAILED`).
- Le **1er process** (harnais qui lance l'échantillon via son interpréteur) n'est PAS signalé — le
  run est déjà tracé par `sandbox_info`. Seuls les **children** et mutations filesystem sont relevés.
- Les accès loader/bibliothèques système (`/lib`,`/usr/lib`,`/usr/local/lib`,`/etc`, ...) et les
  lectures de `/analysis/input` sont filtrés (`normalizer.py`), pour distinguer l'activité de
  l'infrastructure du comportement de l'échantillon (brief §9).
- Bug corrigé : `emit(..., result="blocked")` entrait en collision avec le paramètre `result` de
  `emit()` → `TypeError` avalé par le try → les events réseau étaient silencieusement perdus.
  Renommé en `blocked=True`.

## M4 — Static / Signature Analysis

### D-10 : Moteur de règles statiques pur-Python (YARA différé, sans dépendance native)
- M4 (`app/analyzers/static/`) est un **moteur de règles déclaratif pur-Python** : un `StaticRule`
  déclare des patterns (`byte_patterns` insensibles à la casse, `regexes` sur vue latin-1, `hexes`),
  une `category`, une `severity`, une `confidence` et des `tags`. `match_rule()` ne fait que de la
  correspondance lexicale bornée — **jamais d'exécution**, pas de réseau, pas de subprocess.
- **Pourquoi pas YARA maintenant :** `yara-python` est un binding natif (libyara compilée) absent du
  projet et risqué à installer sur Windows ; le brief demande de ne pas ajouter de dépendance sans
  justification. Le modèle `StaticRule` est volontairement aligné sur la sémantique YARA (patterns +
  métadonnées + sévérité) pour pouvoir brancher un backend YARA derrière `match_rule` plus tard sans
  toucher à l'analyseur ni au schéma de finding.
- **Source = `static_analysis`** (pas de verdict direct). Risque/verdict dérivés par l'orchestrateur
  comme pour M2/M3.
- **Borné :** lecture limitée à `settings.static_max_scan_bytes` (défaut 2 Mo), evidence plafonnée
  (`MAX_EVIDENCE_MATCHES`), regex compilées en `re.ASCII` (sémantique + perf), et garde anti-faux-positif
  `require_mixed` sur le blob base64 (exige majuscule+minuscule+chiffre pour écarter les remplissages
  mono-caractère comme `xxxx...`).
- **M3 reste inconditionnel :** le pipeline reste linéaire `fast_scan → static → sandbox` ; déclencher
  M3 seulement sur suspicion statique est une optimisation future (non implémentée, le risque agrège
  déjà les findings des trois).

### D-11 : YARA first-class, règles sélectionnées et payload FileAnalysis JSON
- M4 ajoute `YaraAnalyzer` après l'analyse structurelle, sans subprocess : `RuleSetManager` charge
  uniquement les chemins explicitement listés dans `backend/rules/yara/manifest.json`, compile chaque
  fichier séparément et isole les erreurs de compilation ; `YaraEngine` scanne des bytes bornés avec
  timeout et limite de résultats.
- Version réellement validée : `yara-python 4.5.4`; version d'analyseur :
  `yara:4.5.4|ruleset:0f935701`. Le SHA complet est conservé dans le manifest et dans l'evidence.
- Upstream exact : `Yara-Rules/rules` commit
  `0f93570194a80d2f2032869055808b0ddcdfb360`, licence GPL-2.0. Sélection : DDE et VBA macro
  (maldocs), XMRig (malware), `inject_thread` (capabilities). Les règles projet sont séparées.
  Les index upstream globaux, `deprecated`, `mobile_malware` et les règles nécessitant `pe/hash`
  ne sont pas chargés.
- `AnalysisResult.payload` porte le modèle normalisé `FileAnalysis` : `metadata`, `hashes`,
  `structure`, `objects`, `indicators`, `features`. Aucun nouveau modèle DB/migration n'est requis
  au stade MVP ; les findings restent dans le schéma Finding existant.
- Analyse Office via `oletools 0.60.2` uniquement pour inspection OLE/VBA ; aucune macro, aucun
  script et aucun objet embarqué n'est exécuté.

## M5 — Dynamic / Behavioral Analysis

### D-12 : Éligibilité explicite à 2 niveaux + monitoring borné (réutilise M3)
- `DynamicAnalyzer` (package `app/analyzers/dynamic/`) remplace `SandboxAnalyzer` dans le pipeline et
  **réutilise** le moteur d'exécution M3 (`SandboxRunner`/`SandboxPolicy`/entrypoint strace) : aucune
  logique d'exécution n'est dupliquée. Le nom d'analyseur reste **`sandbox`** (source des findings
  inchangée) pour ne pas casser M1-M3 ; version bumpée `0.3.0 → 0.4.0`.
- **Politique d'éligibilité** (2 niveaux) : exécutables/scripts (shebang, ELF/PE, extensions scripts)
  dans la limite `dynamic_max_file_mb` ; documents non exécutables exécutés **seulement** si M4 a déjà
  produit un finding HIGH/CRITICAL. Chaque skip est explicite : décision
  `not_eligible/skipped_by_policy/executed/timeout/execution_error/sandbox_error` + raison, persistées
  dans `AnalysisResult.payload` et dans l'evidence du finding `sandbox_info` (INFO, poids 0 → un PDF
  bénin skippé reste `safe risk=0`, le smoke M1 reste vert).
- **Findings comportementaux M5** (evidence-only, mêmes règles que M3) : `shell_execution`,
  `suspicious_command` (argv capturé dans le conteneur, cap 16 args), `dns_request` (tentative port 53,
  bloquée). Le premier process (harnais interpréteur) est ignoré — un script bénin reste propre.
- **Bornes** : `SANDBOX_MAX_EVENTS` (défaut 2000) dans le conteneur, lecture des logs conteneur
  plafonnée à `dynamic_max_output_mb` côté runner. Réseau : DENY par défaut (inchangé), aucune
  observation DNS active — uniquement détection lexicale du port 53.
- Pas de nouveau modèle DB : le payload M5 passe par `AnalysisResult.payload` (comme M4).

## M6 — File Redis (worker asynchrone)

### D-14 : File Redis Streams remplaçant le polling DB (découplage API → workers)
Le polling DB de D-01 est remplacé par une file **Redis Streams** (stream `sandbox:scans`, consumer
group `sandbox:workers`) : `POST /api/scans` crée le scan en DB (QUEUED) puis **enqueue un job**
(`XADD`); les workers lisent la file (`XREADGROUP`) au lieu de poller `FOR UPDATE SKIP LOCKED`.
- **Payload = métadonnées uniquement** : le job transporte seulement `scan_id` (et jamais le contenu
  du fichier, qui reste adressé par `{sha256}.bin` dans `storage/uploads`).
- **Concurrence bornée, inchangée** : `worker_max_threads` (4) avec **un consommateur par thread**
  (`consumer-{i}`), `XREADGROUP` bloquant (délai `redis_block_timeout_ms`, 5 s).
- **Fiabilité / at-least-once** : `XACK` uniquement après état terminal (`COMPLETED`/`FAILED`) ;
  `XAUTOCLAIM` re-délivre les jobs orphelins après `redis_visibility_timeout_s` (600 s) ; le claim est
  **idempotent** (scan QUEUED, ou PROCESSING avec lease expirée — avec purge des résultats partiels ;
  un scan terminal est acké et ignoré, pas de double pipeline) ; au démarrage, les scans QUEUED oubliés
  sont re-enqueue (rescue sweep) ; la consumer group s'auto-répare (`NOGROUP` → recréation).
- **Découplage immédiat** : la submission ne dépend plus de l'état des workers ; en cas d'échec Redis à
  l'enqueue, `POST /api/scans` répond **503** et la ligne scan créée est supprimée (rollback).
- **Schéma DB / pipeline M1–M5 / `SandboxPolicy` inchangés** : seule la couche de dispatch change.
- **Mesure "après" (même corpus/scripts/config, environnement courant)** : 90 fichiers → **40,34 s** →
  **133,9 files/min** (submission 6,55 s, avg 6,8 s, median 5,62 s, p95 15,69 s, max 33,99 s,
  0 échec, 0 conteneur orphelin) vs. D-13 : 199,79 s → 27 files/min. Réserve honnête : l'écart inclut
  des facteurs d'environnement (Docker Desktop chaud après les runs de validation, charge machine) ;
  le cycle de vie des conteneurs reste le coût par fichier pour les échantillons effectivement
  sandboxés (p95 15,69 s). Preuves : `validation/m6_validation/results/raw_scan_results.before_redis.json`
  et `raw_scan_results.after_redis.json`.

## Décisions ouvertes / à confirmer

### D-13 : Débit du worker + capture argv strace (état courant pré-handoff)
- Le worker conserve l'architecture MVP de D-01 (threads + `FOR UPDATE SKIP LOCKED`) mais fonctionne
  désormais avec **4 threads bornés**, un poll de **0,1 s** et **sans délai d'inactivité entre deux
  jobs en file** (`_tick` ne dort que si la file est vide). Ne change pas `SandboxPolicy`.
- `strace` capture les chaînes jusqu'à **256 octets** (`-s 256`, borné par `SANDBOX_STRACE_STRING_SIZE`,
  `_string_args` et `MAX_EVENTS`) — corrige la troncature argv à 32 octets qui masquait la fin de
  certains motifs `suspicious_command`.
- Mesures M6 (état au handoff) : 90 fichiers → 199,79 s → 27 files/min ; le goulot mesuré est le
  cycle de vie des conteneurs Docker Desktop (~14–30 s/conteneur), voir
  `validation/m6_validation/results/SANDBOX_LIFECYCLE_PROFILE.md`. Non optimisé (diagnostic seulement).
  **Depuis :** la file Redis (D-14) retire le polling DB ; statistiques avant/après dans D-14.

- Calibration des seuils de risque (voir D-02).
- Valeur cible Fast Scan : §2.5 stipule `<20ms`, mais c'est un **objectif de benchmark**, pas une
  contrainte à forcer. À mesurer en M2.
