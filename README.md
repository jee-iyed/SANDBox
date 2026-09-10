# Document Security Scanner

Plateforme SaaS d'analyse et de sanitisation de documents (FastAPI + PostgreSQL + **Redis**),
développée phase par phase selon un brief en 18 phases. Volume cible : ~5 000 docs/mois.

## Architecture (résumé)

- **Upload** → **async** : `POST /scans` → scan créé en DB (`QUEUED`) + job poussé sur une **file Redis
  Streams** (`sandbox:scans`, consumer group `sandbox:workers`) → worker en arrière-plan →
  `COMPLETED | FAILED`. La file transporte uniquement `scan_id` (métadonnées, jamais le contenu).
- **Pipeline** (orchestrator) : fast scan → static/YARA → sandbox dynamique → IA → corrélation/risque
  → verdict/action → CDR/quarantaine.
- **Finding normalisé** (schéma obligatoire) : `type / value / source / severity / confidence /
  evidence / timestamp / location / tags / analyzer_version`.
- **Décisions et état de chaque phrase** : voir [`DECISIONS.md`](DECISIONS.md) et
  [`SECURITY.md`](SECURITY.md).

## État d'avancement

- ✅ **M1 — Socle + async** : structure cible, modèles, schéma Finding, cycle async, sandbox isolée.
- ✅ **M2 — Fast Scan réel** : magic bytes + OOXML/ODF, entropie bornée, signatures simples, mismatch
  extension/contenu. Benchmark : mean ~0.3–0.5 ms, p95 ≤0.8 ms sur environnement de test (largement
  sous l'objectif <20 ms).
- ✅ **M3 — Sandbox dynamique** : exécution contrôlée de l'échantillon dans un conteneur durcé, `strace -f`,
  observation process / filesystem / réseau, statuts distincts (`completed/timeout/crashed/
  failed_to_start/resource_limit`), normalisation en Findings (`source=sandbox`), isolation validée
  (réseau coupé, rootfs RO, non-root → timeout correctement appliqué, tentative réseau bloquée et
  observée). Le sandbox **ne décide jamais** de verdict : il produit des findings ; le moteur de risque
  (orchestrator) dérive risque → verdict → action.
- ✅ **M4 — Static/Signature** : inspection statique des octets (jamais d'exécution) via un moteur de
  règles déclaratif pur-Python (`source=static_analysis`) — signatures de test (EICAR), commandes
  suspectes (PowerShell encodé, reverse shell), scripts obfusqués, URLs/IPs, blobs base64/hex. Borné à
  `static_max_scan_bytes`, sans réseau ni subprocess. Le modèle de règle anticipe l'ajout de YARA.
- ✅ **M4 — YARA + structure** : `YaraEngine` + `RuleSetManager` versionnés (`yara-python 4.5.4`,
  ruleset `0f93570194a80d2f2032869055808b0ddcdfb360`), sous-ensemble approuvé GPL-2.0 de
  `Yara-Rules/rules`, règles projet séparées, findings `source=yara`, payload `FileAnalysis` dans
  `analysis_results.payload`, analyse ZIP/PDF/Office bornée et `oletools` sans exécution de macros.
- ✅ **M5 — Analyse dynamique** : `DynamicAnalyzer` (source `sandbox`, v0.4.0) avec **politique
  d'éligibilité explicite à 2 niveaux** — exécutables/scripts par nature, documents non exécutables
  seulement si M4 a produit un finding HIGH/CRITICAL ; sinon `not_eligible`/`skipped_by_policy`
  observable dans `AnalysisResult.payload` et l'evidence `sandbox_info`. Réutilise le sandbox durci M3
  (`strace -f`, réseau DENY, caps CPU/RAM/PIDs, cleanup garanti) + findings comportementaux
  `shell_execution`, `suspicious_command`, `dns_request` et caps `max_events`/`max_output_mb`.
`strace -s 256` preserves bounded command evidence beyond its 32-byte default; the worker is
   dispaché par une file Redis Streams (M6) avec un pool borné de 4 consommateurs.
   L'analyse dynamique est **bornée** : ce n'est pas une sandbox commerciale complète.
- ✅ **M6 — File Redis** : découplage API → workers via **Redis Streams** (`sandbox:scans` /
  `sandbox:workers`). `POST` enqueue après création du scan (202) ; workers = 4 consommateurs bornés
  (`XREADGROUP` bloquant) ; `XACK` après état terminal, `XAUTOCLAIM` pour les jobs orphelins
  (visibilité 600 s), claim idempotent (pas de double pipeline), rescue sweep des QUEUED au
  démarrage, auto-heal `NOGROUP` ; erreur Redis à l'enqueue → `503` + rollback. Pipeline M1–M5 et
  schéma inchangés. Voir [D-14](DECISIONS.md).
- ⬜ M6–M8 (reste) : corrélation/risque (calibrage), IA, CDR, productisation.

## Supervisor Test / Current Status

- **M1–M5 functional validation : PASS** — full regression suite green (smoke, fast scan 27/27,
  sandbox behavior 8/8 + normalizer/isolation, static 14/14 + 10/10, YARA 7/7 + 3/3, M5 8/8 + 14/14).
- **YARA validation : PASS** (TP 27 / FP 0 / FN 0 sur corpus synthétique).
- **Dynamic behavioral validation : PASS** (TP 10 / FP 0 / FN 0 au niveau source ; 2 FN type
  `suspicious_command` documentés, corrigés depuis par `strace -s 256`).
- **Sandbox security validation : PASS** (réseau DENY, rootfs RO, non-root, `cap_drop=ALL`,
  `no-new-privileges`, limites CPU/RAM/PIDs, cleanup garanti — 0 conteneur orphelin).
- **Redis queue validation : PASS** — unitaire `test_redis_queue.py` 13/13 (enqueue, ack, autoclaim,
  idempotence, 503+rollback, redélivrance des jobs) + E2E `e2e_redis_queue.py` 5/5 (submit rapide,
  jobs en file, terminaison, persistance, duplicata sans corruption).
- **Performance target (5 000 files / 60 min) : ACHIEVED (benchmark local)** — avec la file Redis,
  même corpus de 90 fichiers : **40,34 s → 133,9 files/min** (submission 6,55 s, avg 6,8 s,
  median 5,62 s, p95 15,69 s, 0 échec, 0 orphelin) contre 199,79 s → 27 files/min avant (D-13).
  Le résultat reste environnement-dépendant ; pour les échantillons effectivement sandboxés, le cycle
  de vie des conteneurs Docker Desktop reste le coût dominant par fichier (p95 15,69 s). Preuves :
  `validation/m6_validation/results/raw_scan_results.before_redis.json` /
  `raw_scan_results.after_redis.json`.
- **No real malware used** — tous les échantillons de validation sont synthétiques et inertes.
- Validation supplémentaire M6 : [`validation/m6_validation/`](validation/m6_validation/) (corpus 90
  fichiers, scripts de benchmark, matrices de détection,
  [profilage du cycle de vie sandbox](validation/m6_validation/results/SANDBOX_LIFECYCLE_PROFILE.md),
benchmark avant/après file Redis `raw_scan_results.before_redis.json` /
   `raw_scan_results.after_redis.json`).
- **Secure File Access validation : PASS** — `test_secure_access.py` 40/40 (state machine
  fail-closed, sanitization, storage isolé, oversize, content placeholder) + E2E `e2e_secure_access.py`
  (bénin → AUTHORIZED, suspicieux → BLOCKED/QUARANTINED jamais accessible en /content, 404/501/422).
  Voir [D-16](DECISIONS.md).

## Secure File Access Architecture (Gateway)

SANDBox n'est **pas** un site où l'utilisateur télécharge puis re-scanne des fichiers à la main. Le
produit est une **Secure File Access Gateway** : une plateforme cliente (messagerie, GED, application
d'entreprise) transmet le fichier ; SANDBox le scanne **automatiquement** (M1 → M5, file Redis) avant
que l'utilisateur ne puisse y accéder de façon sécurisée.

### Modèle cible (pas le modèle historique)

```
Modèle à éviter :
    Email → Downloads/invoice.pdf → machine locale → ouverture dans l'appli locale avant analyse

Modèle cible :
    Plateforme cliente (Email / GED / App)
        │  clic "Open Securely" / "View"
        ▼
    SANDBox Secure File Access Gateway (API :8001)
        │  POST /api/secure-access  (fichier OU référence sécurisée)
        ▼
    Scan automatique (Scan + Redis Streams sandbox:scans → worker → M1→M5)
        ▼
    Moteur de risque déterministe → verdict/action
        ▼
    SAFE            → AUTHORIZED       → preview sécurisée (placeholder contrôlé)
    SUSPICIOUS      → BLOCKED          → analyse visible, fichier jamais exposé
    MALICIOUS       → QUARANTINED      → fichier isolé en quarantaine
    FAILED/EXPIRED  → DENY (fail-closed, jamais ALLOW)
```

Le fichier original n'est **jamais** téléchargé sur la machine de l'utilisateur avant la décision ; le
frontend affiche uniquement la décision produite par le backend.

### Cycle de vie d'un accès sécurisé

```
SecureAccess ──wraps──> Scan ──enqueue──> Redis Streams (existant) ──> worker ──> M1–M5 ──> Risk/verdict
                                                                                            │
      POLICY updated (Service observe le scan ; aucun pipeline dupliqué) <──────────────────┘
```

Le service `app/secure_access/` **observe** l'état du scan (state machine `states.py`) ; il ne
réimplémente ni la file, ni le pipeline, ni le moteur de risque.

- **MODE 1 — upload** : la plateforme envoie le fichier en `multipart/form-data`.
- **MODE 2 — référence externe** : JSON `{source_type:"external_reference", source_token, filename}`.
  La récupération externe authentifiée n'**est pas implémentée** (réponse 501) ; SANDBox ne fait jamais
  de fetch aveugle d'URL. Interface : `ExternalReferenceResolver`.
- **Stockage temporaire** : `backend/storage/sandbox_storage/{pending,processing,authorized,quarantine}/`
  (noms = UUID générés, jamais le nom client ; jamais exposé par le serveur web). Une copie
  `uploads/<sha256>.bin` (logique scan existante) alimente le pipeline M1–M5.
- **Contenu sécurisé** : `/content` ne renvoie aujourd'hui qu'un **placeholder** contrôlé
  (« Secure preview is not yet configured ») — le rendu/sanitisation dans le sandbox n'est pas encore
  implémenté, et le projet ne prétend pas ouvrir localement le document original.
- **Authentification** : **endpoint prototype non authentifié** ; en production il DOIT être derrière
  une passerelle authentifiée de la plateforme cliente (token d'intégration).
- **Limitation** : SANDBox ne peut pas intercepter magiquement un téléchargement Gmail/Outlook ; une
  intégration réelle de la plateforme cliente est requise. Les écrans React (`/secure-access`)
  **simulent** cette plateforme à des fins de démonstration du contrat.

### API

| Méthode | Route | Description |
|---|---|---|
| POST | `/api/secure-access` | Crée la demande (MODE 1 fichier / MODE 2 référence → 501) et enfile le scan |
| GET | `/api/secure-access/{access_id}` | État courant + décision (reconciliation fail-closed) |
| GET | `/api/secure-access/{access_id}/content` | Contenu sécurisé (placeholder) **uniquement si AUTHORIZED** |

## Démarrage rapide

### 1. Infrastructure (PostgreSQL + Redis)

```powershell
docker compose up -d
```

> Docker Desktop doit être démarré (daemon actif) avant.

### 2. Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

- API docs Swagger : http://127.0.0.1:8001/docs
- Health check : http://127.0.0.1:8001/api/health

> ⚠️ Le port 8000 est réservé à un autre projet (IOC-hunter) : ce backend utilise **8001**.

### 3. Reset DB dev (en cas de changement de schéma)

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\reset_db.py   # drop/recréer le schéma
```

### 4. Tests

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\build_sandbox_image.py        # rebuild l'image sandbox-runner
.\.venv\Scripts\python.exe tests\test_sandbox_normalizer.py      # normalisation findings (unitaire, sans Docker)
.\.venv\Scripts\python.exe tests\test_sandbox_isolation.py       # isolation sandbox (Docker requis)
.\.venv\Scripts\python.exe tests\test_static_analyzer.py         # analyse statique M4 (unitaire, sans Docker)
.\.venv\Scripts\python.exe tests\e2e_fast_scan.py http://127.0.0.1:8001   # régression M2 fast scan
.\.venv\Scripts\python.exe tests\e2e_sandbox_behavior.py http://127.0.0.1:8001  # comportements M3 (process/file/réseau)
.\.venv\Scripts\python.exe tests\e2e_static_analysis.py http://127.0.0.1:8001  # analyse statique M4 (E2E)
.\.venv\Scripts\python.exe tests\test_yara_m4.py                    # compilation + moteur YARA (unitaire)
.\.venv\Scripts\python.exe tests\e2e_m4_yara.py http://127.0.0.1:8001 # corpus YARA + structure (E2E)
.\.venv\Scripts\python.exe tests\test_dynamic_m5.py                  # M5 politique éligibilité + findings (unitaire)
.\.venv\Scripts\python.exe tests\e2e_dynamic_m5.py http://127.0.0.1:8001 # M5 exécution dynamique bornée (E2E)
.\.venv\Scripts\python.exe tests\smoke_test.py http://127.0.0.1:8001   # flux async complet M1
.\.venv\Scripts\python.exe tests\test_redis_queue.py                  # file Redis (unitaire, sans Docker ni serveur)
.\.venv\Scripts\python.exe tests\e2e_redis_queue.py http://127.0.0.1:8001 # file Redis (E2E : enqueue, terminaison, duplicata)
.\.venv\Scripts\python.exe tests\test_secure_access.py                # Secure File Access (unitaire, sans serveur)
.\.venv\Scripts\python.exe tests\e2e_secure_access.py http://127.0.0.1:8001 # Secure File Access (E2E : bénin/suspicieux + /content fail-closed)
.\.venv\Scripts\python.exe scripts\bench_static.py               # benchmark M4 (mean/median/p95)

# Inspection/version YARA
.\.venv\Scripts\python.exe -c "import yara; print(yara.__version__)"
# Recompiler les règles sélectionnées et vérifier le manifest
.\.venv\Scripts\python.exe tests\test_yara_m4.py
```

## API

| Méthode | Route | Description |
|---|---|---|
| GET | `/api/health` | État du service + DB |
| POST | `/api/scans` | Upload + scan : `202` + `{status: queued}` |
| GET | `/api/scans` | Liste des scans |
| GET | `/api/scans/{id}` | Détail d'un scan + findings |
| POST | `/api/secure-access` | Secure File Access : fichier (MODE 1) ; référence externe (MODE 2 → 501) |
| GET | `/api/secure-access/{access_id}` | État + décision de l'accès sécurisé |
| GET | `/api/secure-access/{access_id}/content` | Contenu sécurisé si AUTHORIZED (placeholder contrôlé) |
| GET | `/api/system/workers` | Métriques non sensibles : workers, file Redis, débit/latence sur fenêtre glissante |

## Parallel workers and QR analysis

Workers process independent scans in parallel. M1–M5 execute sequentially within each worker.

`POST /api/scans` stores the attachment under controlled storage and adds its ID to the
Redis Stream `sandbox:scans`. Consumers in the `sandbox:workers` group claim independent
jobs with `XREADGROUP`; stale pending jobs are recovered with `XAUTOCLAIM`; `XACK` is only
sent after a terminal scan state. Set `WORKER_MAX_THREADS` to configure the bounded number
of in-process consumers (start comparison runs at 2 through 7; do not assume seven is best).

After M5, `QRAnalyzer` visually examines PDF pages using PyMuPDF rendering, Pillow and
pyzbar. Page count, rendering resolution, pixel count, decoded-code count and elapsed time
are bounded by `QR_*` settings. The structured result contains detected payloads and URLs.
It never performs network reputation lookup and never changes the deterministic risk verdict.
Future reputation enrichment must remain optional, timeout-bounded and cacheable. No LLM,
Hermes runtime, Ollama runtime or model download is part of this production path.

### Performance methodology

Use the same corpus and security configuration for each `WORKER_MAX_THREADS` value of 2, 3,
4, 5, 6 and 7. Record completed scans—not submission time—plus elapsed time, files/minute,
files/second, success/failure counts, average and p95 latency, Redis pending entries, CPU and
memory. The dashboard's throughput is a live five-minute rolling value; it is not benchmark
history. The saved M6 result is 27 files/minute and does **not** demonstrate the 350
files/minute target. Docker sandbox lifecycle remains the likely primary bottleneck until a
controlled scalability run establishes otherwise; isolation controls must not be disabled to
meet the target.
