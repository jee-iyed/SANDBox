# SECURITY — Document Security Scanner

Décisions et règles de sécurité transverses au projet. Statut : vivant.

## Principes de base

- **L'IA (LLM) n'est jamais un contrôle de sécurité** : elle ne produit ni verdict ni action.
- Séparer **risque** (score quantitatif) / **verdict** / **action** (politique) — cf. `DECISIONS.md`.
- Sandbox = **gate dur**, sans bypass.

## Analyse des fichiers non fiables

- Les uploads sont traités comme **non fiables** par défaut.
- **Pas de `--privileged`, pas de host networking, pas d'accès au socket Docker hôte** pour les
  fichiers analysés.
- Le runner sandbox (Docker) est durci :
  - image `docscan/sandbox-runner`, utilisateur non-root (uid 10001),
  - `network_disabled=true` (réseau coupé),
  - rootfs **read-only** + `tmpfs` `/tmp` (`noexec,nodev,nosuid`),
  - `cap_drop=ALL`, `no-new-privileges=true`,
  - limites CPU / RAM / PIDs (configurables dans `core/config.py`).
- `read_only=true` interdit `put_archive` → donc **bind mount read-only** de `storage/uploads` +
  analyses content-adressées `{sha256}.bin` (voir `tests/test_sandbox_isolation.py`).

## M3 — Dynamic Sandbox Analysis

- **Modèle :** chaque échantillon est traité comme hostile. Le sandbox **n'exécute rien en dehors**
  d'un conteneur jetable (`sandbox-<uuid>`), jamais réutilisé, toujours supprimé (DESTROY garanti).
- **Observation :** l'entrypoint in-conteneur (`sandbox_runner/sandbox.py`) lance l'échantillon sous
  `strace -f` + `timeout` ; les événements **process / filesystem / réseau** sont parses en JSON.
  Statuts distincts : `completed`,`timeout`,`crashed`,`failed_to_start`,`resource_limit`
  (les échecs ne sont PAS réduits à `FAILED`).
- **Réseau :** `network_disabled=true` → toute tentative `connect()/sendto()` **échoue** et est
  enregistrée `blocked=true`. On n'invente jamais de connexion réussie.
- **Le sandbox ne décide pas le verdict** : il émet des findings `source=sandbox` (evidence). Risque
  / verdict / action sont dérivés par l'orchestrateur (moteur de risque existant).
- **Bruit filtré :** accès loader/bibliothèques système et lectures de la partition d'entrée
  (`/lib`,`/usr/lib`,`/usr/local/lib`,`/etc`,`/analysis/input`, ...) ne produisent pas de finding ;
  le 1er process (harnais qui lance l'échantillon) n'est pas signalé non plus — seuls les children
  et mutations sont relevés.

### Limitation Docker Desktop (documentée ici, comme convenu)

- Docker Desktop applique **`noexec` de force sur TOUS les `tmpfs`** (même sans l'option) → il est
  impossible d'exécuter depuis `/tmp` ou `/exec`. 
- En conséquence, l'échantillon est exécuté **depuis le bind mount ro `/analysis/input`**, qui est
  exécutable (9p/drvfs, pas de `noexec`). Le rootfs reste `ro`, rien ne peut être écrit sur l'entrée.

## M4 — Static / Signature Analysis

- **Jamais d'exécution** : M4 opère sur des octets/texte uniquement. Pas de subprocess, pas de
  `exec`/`eval` du sample, pas d'import dynamique, pas de macro, pas de requête réseau, pas de
  suivi d'URL trouvée.
- **Borné :** lecture plafonnée à `static_max_scan_bytes` (2 Mo), nombre de correspondances par règle
  plafonné (`MAX_EVIDENCE_MATCHES`), regex `re.ASCII` (pas de backtracking catastrophique ; patterns
  sans quantificateurs imbriqués). Les limites de taille d'upload existantes (`max_upload_mb`) restent
  appliquées en amont.
- **Evidence-only :** findings `source=static_analysis` ; jamais de verdict direct. Le moteur de risque
  agrège sévérité × confiance.
- **EICAR :** la règle `static_eicar_signature` détecte la chaîne EICAR (test AV canonique). Les tests
  ne l'écrivent PAS sur disque (l'AV hôte la mettrait en quarantaine) — la correspondance est testée
  en mémoire (`match_rule`).

### M4 — YARA et structure documentaire

- **YARA versionné :** moteur `yara-python==4.5.4`; ruleset upstream fixé au commit
  `0f93570194a80d2f2032869055808b0ddcdfb360`. Le manifest liste chaque fichier approuvé ; aucun
  index global upstream n'est chargé dynamiquement.
- **Séparation licence :** `rules/yara/vendor/yararules/` contient les règles GPL-2.0 upstream avec
  provenance ; `rules/yara/selected/project/` contient les règles SANDBox. Voir `NOTICE.md` et
  `manifest.json`.
- **Compilation/runtime défensifs :** chaque fichier est compilé isolément ; une règle invalide est
  enregistrée comme erreur sans supprimer les autres matches. Le scan YARA est borné à
  `static_max_scan_bytes`, `yara_timeout_s` et `yara_max_matches`.
- **Pas d'exécution active :** ZIP, PDF, OLE/VBA et objets embarqués sont lus comme données. `oletools`
  est utilisé pour détecter/inspecter VBA ; les macros ne sont jamais lancées. Les URLs ne sont pas
  suivies et aucun réseau n'est ouvert.
- **Archive safety :** limites d'entrées, ratio de compression, taille décompressée et profondeur ;
  les chemins d'archive sont des métadonnées, jamais des chemins d'écriture host.
- **Payload normalisé :** chaque analyse structurelle/YARA persiste un JSON `FileAnalysis` borné dans
  `analysis_results.payload`; les détections sont des findings evidence-only et passent ensuite par
  le moteur de risque existant.

### M5 — Dynamic / Behavioral Analysis (extension de M3)

- **Durcissement hérité et intact** : M5 réutilise le conteneur M3 (`cap_drop=ALL`,
  `no-new-privileges`, rootfs RO, tmpfs noexec, non-root, réseau coupé, limites CPU/RAM/PIDs, timeout,
  DESTROY garanti) et ajoute les caps `max_events`/`max_output_mb`.
  Aucun contrôle n'a été affaibli.
- **Éligibilité** : pas d'exécution systématique. Exécutables/scripts ou documents flaggés HIGH/CRITICAL
  par M4 uniquement ; sinon skip explicite et observable (`not_eligible`/`skipped_by_policy`).
- **Politique réseau : DENY par défaut.** Aucun accès Internet, aucune connexion entrante hôte. Les
  tentatives (dont port 53) sont enregistrées `blocked=true` en evidence — on n'invente jamais de
  connexion réussie.
- **Bornes** : events ≤ `dynamic_max_events`, sortie conteneur lue ≤ `dynamic_max_output_mb`, `strace`
  captures at most 256 bytes per string, argv is capped (16 args × 256 octets), evidence remains
  bounded. Un timeout, un crash ou une erreur Docker ne
  cassent ni le scan ni le worker (`sandbox_error` explicite, cleanup `finally`).
- **Pas d'exécution d'artefacts extraits**, pas d'analyse récursive, pas de macro/script hôte.
- L'analyse dynamique est **bornée et n'est pas équivalente à une sandbox commerciale complète**.

## File Redis (worker asynchrone, M6)

- **Métadonnées uniquement** : un job ne transporte que `scan_id` — jamais le contenu du fichier. Le
  contenu reste adressé par `{sha256}.bin` dans `storage/uploads` ; les workers le retrouvent via le
  serveur, sans chemin fourni par le client.
- **Payloads de file = non fiables** : `scan_id` est validé comme UUID avant toute opération
  DB/Redis ; rien n'est exécuté à partir des messages. Aucun subprocess/shell n'est déclenché par la
  file : le pipeline reste celui, inchangé, d'`orchestrator/scanner.py` (D-04).
- **Pas de double analyse** : le claim est idempotent — QUEUED, ou PROCESSING avec lease expirée
  (résultats partiels purgés avant re-exécution) ; un scan déjà terminal est acké et ignoré.
- **Fiabilité bornée** : `XACK` uniquement après état terminal, `XAUTOCLAIM` re-délivre les jobs
  orphelins après le timeout de visibilité (600 s), rescue sweep des QUEUED au démarrage.
- **Connexion** : Redis local en loopback par défaut (`redis://localhost:6379/0`). S'il est exposé :
  activate `redis_username`/`redis_password`, réseau dédié, **jamais de secret dans les messages**.
  Voir D-14 dans `DECISIONS.md`.

## Secrets / artefacts malveillants

- **Jamais de secrets/clés commités** (`.env` est ignoré ; seul `.env.example` est versionné).
- **Jamais de malware réel** déposé/committé dans le dépôt — les tests utilisent des échantillons
  inertes/bénins.

## Stockage

- Répertoires par rôle séparés : uploads / quarantine / sanitized / reports
  (`storage/*`), avec `core/security.py` : `safe_join`, `quarantined_upload_path`.
- Accès contenu-adressé (`{sha256}.bin`) pour éviter collisions et déni de chemin.

## API

- Limite de taille d'upload (`MAX_UPLOAD_MB`, défaut 50) — rejet 413.
- CORS ouvert (`*`) en dev uniquement → à restreindre avant toute exposition publique.

## À faire / décalé

- AuthN/AuthZ (API keys / tenants) — à traiter en phase de productisation (M8+).
- Rate limiting — M8+.
- Vérif antivirus déléguée (ClamAV) si besoin — à décider.
