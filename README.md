# Document Security Scanner

Plateforme SaaS d'analyse et de sanitisation de documents (FastAPI + PostgreSQL),
développée phase par phase selon un brief en 18 phases. Volume cible : ~5 000 docs/mois.

## Architecture (résumé)

- **Upload** → **async** : `POST /scans` → `202 QUEUED` → worker en arrière-plan →
  `COMPLETED | FAILED`.
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
  `strace -s 256` preserves bounded command evidence beyond its 32-byte default; the worker uses
  four bounded DB-locked workers and does not sleep between already queued scans.
  L'analyse dynamique est **bornée** : ce n'est pas une sandbox commerciale complète.
- ⬜ M6–M8 : corrélation/risque (calibrage), IA, CDR, productisation.

## Supervisor Test / Current Status

- **M1–M5 functional validation : PASS** — full regression suite green (smoke, fast scan 27/27,
  sandbox behavior 8/8 + normalizer/isolation, static 14/14 + 10/10, YARA 7/7 + 3/3, M5 8/8 + 14/14).
- **YARA validation : PASS** (TP 27 / FP 0 / FN 0 sur corpus synthétique).
- **Dynamic behavioral validation : PASS** (TP 10 / FP 0 / FN 0 au niveau source ; 2 FN type
  `suspicious_command` documentés, corrigés depuis par `strace -s 256`).
- **Sandbox security validation : PASS** (réseau DENY, rootfs RO, non-root, `cap_drop=ALL`,
  `no-new-privileges`, limites CPU/RAM/PIDs, cleanup garanti — 0 conteneur orphelin).
- **Performance target (5 000 files / 60 min) : NOT YET ACHIEVED** — benchmark local 90 fichiers :
  199,79 s → **27 files/min** (cible 90 files/min). Le goulot mesuré est le cycle de vie des
  conteneurs Docker Desktop (create+start+remove ≈ 14–30 s/conteneur) dans l'environnement courant,
  pas le code d'analyse (exécution+strace+collecte < 0,2 s). Voir
  [`validation/m6_validation/results/SANDBOX_LIFECYCLE_PROFILE.md`](validation/m6_validation/results/SANDBOX_LIFECYCLE_PROFILE.md).
- **No real malware used** — tous les échantillons de validation sont synthétiques et inertes.
- Validation supplémentaire M6 : [`validation/m6_validation/`](validation/m6_validation/) (corpus 90
  fichiers, scripts de benchmark, matrices de détection, profilage du cycle de vie sandbox).

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
