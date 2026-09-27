# CIF — Cognitive Intelligence Framework for Cybersecurity

This is a runnable capstone prototype of the architecture in **Capstone Review_1_CIF.pptx**. It demonstrates evidence ingestion, a local knowledge graph, retrieval-augmented threat reasoning, iterative belief updates, four independent verification agents, and an explainable JSON assessment.

## What works immediately

The included demo runs using only Python's standard library and sample records. It does not need a GPU, Neo4j server, API key, or downloaded dataset. The built-in baseline is deliberately transparent and labels its confidence as a heuristic triage score, not a calibrated probability. An optional local Ollama connection can use Llama 3.1 8B Instruct to draft a hypothesis grounded in retrieved evidence; the rule-based checks still verify the result.

## Windows setup

1. Install Python 3.10 or newer and open PowerShell in this project folder.
2. Create and activate an isolated Python environment:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` in that same window and activate again.
3. Run the included end-to-end demo directly from the source folder:

   ```powershell
   python run.py demo
   ```

   The project has no required third-party Python packages or install step.
4. Open the result:

   ```powershell
   Get-Content .\reports\demo.json
   ```

   Results are written to `reports/demo.json`. Open it in VS Code or run `Get-Content .\reports\demo.json`.

## Where datasets go

Keep downloaded/source data under `data/raw/`. Preserve the original files; CIF reads them and writes its compact index under `reports/`. The checked-in `data/sample/` folder is a tiny teaching example, not a substitute for the full datasets. Do not put secrets, private logs, or production telemetry in a public copy of this project.

Supported input formats:

| Source | Put it here | Supported form |
|---|---|---|
| CTI text / CSTI records | `data/raw/cti/` | `.txt`, `.md`, `.jsonl`, or JSON records |
| MITRE ATT&CK | `data/raw/attack/` | STIX 2.1 bundle JSON (`objects`) |
| NVD / CVE | `data/raw/nvd/` | NVD 2.0 JSON feed (`vulnerabilities`) |
| CISA KEV | `data/raw/kev/` | CSV catalog |
| CICIDS2017 | `data/raw/cicids2017/` | CICFlowMeter CSV files |
| Your alerts | `data/events/` | JSON/JSONL event records (kept out of the knowledge index) |

CSV rows become evidence documents. The default index command keeps at most 2,000 rows **per CSV** to avoid unexpectedly large indexes. Use `--max-csv-rows 0` to read all rows; for large CICIDS2017 files, index only a small selected file or use a row cap first. The prototype keeps the index in a JSON file, so very large production corpora need a vector store and database backend.

### Official dataset starting points

- MITRE ATT&CK STIX 2.1: [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data)
- NVD CVE data: [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds) and [NVD API documentation](https://nvd.nist.gov/developers)
- CISA KEV: [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- CICIDS2017: [Canadian Institute for Cybersecurity dataset page](https://www.unb.ca/cic/datasets/ids-2017.html)

Use each dataset's current terms and citation guidance. Do not copy the entire multi-gigabyte CICIDS2017 archive into the sample folder.

## Index and analyze your data

Create the source folders and copy files into them:

```powershell
New-Item -ItemType Directory -Force data\raw\cti,data\raw\attack,data\raw\nvd,data\raw\kev,data\raw\cicids2017 | Out-Null
```

Build or refresh the evidence index after adding files:

```powershell
python run.py index --data data/raw --output reports/index.json --max-csv-rows 2000
```

Create an event file such as `data/events/my_events.jsonl`, one JSON object per line. Include a stable `case_id` to let CIF update that case's belief when you rerun with new evidence:

```json
{"id":"alert-101","case_id":"case-101","event_type":"network alert","summary":"Repeated remote logons and file changes","src_ip":"198.51.100.20","technique":"T1021"}
```

Run the analysis:

```powershell
python run.py analyze --index reports/index.json --events data/events/my_events.jsonl --output reports/analysis.json --state reports/beliefs.json
```

The report includes the hypothesis, heuristic confidence, matched source excerpts, graph connections, independent agent findings, suggested response, and belief update. Each run saves a belief state; remove or rename `reports/beliefs.json` to start a fresh demonstration.

## Optional Llama 3.1 8B Instruct

The demo works without an LLM. To enable local generation, install [Ollama](https://ollama.com/download), download the model once, and make sure its local service is running:

```powershell
ollama pull llama3.1:8b
python run.py analyze --index reports/index.json --events data/events/my_events.jsonl --output reports/analysis.json --state reports/beliefs.json --llm ollama --model llama3.1:8b
```

The project sends the event and retrieved excerpts to `http://localhost:11434`; it does not send data to a hosted API. An 8B model is resource-intensive. The presentation recommends 16 GB RAM minimum and 32 GB for comfort; GPU support can improve local inference speed. Use `--llm off` for the lighter deterministic baseline.

## How the prototype maps to the capstone

1. **Collection and preprocessing:** reads CTI text/JSONL, ATT&CK STIX JSON, NVD 2.0 JSON, KEV CSV, and CICIDS CSV.
2. **Knowledge graph:** indexes evidence documents as nodes and links extracted CVE, CWE, ATT&CK technique, and named entities; STIX relationships become graph edges.
3. **RAG:** retrieves the most relevant local evidence using transparent lexical matching.
4. **Reasoning:** creates a grounded hypothesis with a deterministic baseline or optional local Llama model.
5. **Belief revision:** persists scores by `case_id`, adds only newly retrieved evidence, and adjusts down when retrieved context signals benign/false-positive evidence.
6. **Multi-agent verification:** separate evidence, graph consistency, threat-intelligence cross-check, and hypothesis-critic agents record their own verdicts and evidence IDs.
7. **Decision:** returns a confidence band, cited evidence, explanation, and response suggestions as JSON.

## Current scope and next research upgrades

This first deliverable is a local, reproducible prototype. Its graph and retrieval index are JSON-backed, entity extraction is intentionally simple, and confidence is heuristic. It does not claim to replace a SOC analyst or to autonomously block traffic. For the next capstone phase, the natural upgrades are Neo4j for graph queries, FAISS/Chroma for embedding search, a calibrated model evaluated against labeled CICIDS flows, richer STIX/NVD/CVE normalization, and documented agent evaluation with false-positive/false-negative measures. The included interfaces keep the first run small and easy to reproduce.

## Troubleshooting

- If a command cannot find its files, run it from the project folder or pass absolute file paths.
- `data/raw` does not exist: create it and copy in source files, or run `python -m cif demo` with the included sample folder.
- No evidence retrieved: check that `--data` points to the extracted folder and the format is one of the supported formats.
- Ollama connection error: start Ollama and run `ollama list`; otherwise use `--llm off`.
- Huge index: lower `--max-csv-rows`, remove unwanted CSVs from the indexing folder, or split data by source and index selected portions.
