from __future__ import annotations

import csv
import hashlib
import json
import re
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

STOP = {"the", "and", "for", "with", "from", "that", "this", "into", "when", "then", "have", "has", "was", "were", "are", "not", "but", "use", "using", "event", "system", "data", "information", "attack", "threat"}
ENTITY_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?|CWE-\d+|APT\s?\d+|[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b")


def _terms(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9][a-z0-9._-]+", text.lower()) if len(t) > 2 and t not in STOP]


def _doc(source: str, title: str, text: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    text = " ".join(str(text).split())
    key = hashlib.sha1((source + "\0" + title + "\0" + text).encode("utf-8")).hexdigest()
    return {"id": key, "source": source, "title": title[:240], "text": text[:12000], "metadata": metadata or {}}


def build_index(folder: Path, max_csv_rows: int = 2000) -> dict[str, Any]:
    if not folder.exists():
        raise FileNotFoundError(f"Data folder does not exist: {folder}. Create it and add supported files first.")
    docs: list[dict[str, Any]] = []
    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        if path.stem.lower() in {"events", "security_events", "my_events"} or "events" in {part.lower() for part in path.parts}:
            continue
        suffix = path.suffix.lower()
        if suffix in {".md", ".txt"}:
            docs.append(_doc(str(path), path.stem, path.read_text(encoding="utf-8", errors="replace")))
        elif suffix == ".jsonl":
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if line.strip():
                    try:
                        rec = json.loads(line)
                        _add_record(docs, nodes, edges, str(path), rec, f"row-{i}")
                    except json.JSONDecodeError:
                        docs.append(_doc(str(path), f"row-{i}", line))
        elif suffix == ".json":
            try:
                obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                _add_json(docs, nodes, edges, str(path), obj, max_csv_rows)
            except json.JSONDecodeError:
                continue
        elif suffix == ".csv":
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for i, rec in enumerate(reader):
                    if max_csv_rows and i >= max_csv_rows:
                        break
                    _add_record(docs, nodes, edges, str(path), rec, f"row-{i+1}")
    # Explicit references in records create graph links, while repeated entities are merged.
    return {"schema_version": 1, "documents": docs, "graph": {"nodes": list(nodes.values()), "edges": _dedupe_edges(edges)}}


def _add_json(docs: list, nodes: dict, edges: list, source: str, obj: Any, limit: int) -> None:
    if isinstance(obj, dict) and isinstance(obj.get("objects"), list):  # ATT&CK/STIX bundle
        refs: dict[str, str] = {}
        for item in obj["objects"]:
            if not isinstance(item, dict):
                continue
            typ = item.get("type", "object")
            name = item.get("name") or item.get("id") or typ
            desc = item.get("description", "")
            doc = _add_record(docs, nodes, edges, source, {"type": typ, "name": name, "description": desc, "external_references": item.get("external_references", [])}, str(item.get("id", name)))
            refs[item.get("id", "")] = doc
        for item in obj["objects"]:
            if item.get("type") == "relationship":
                a, b = refs.get(item.get("source_ref")), refs.get(item.get("target_ref"))
                if a and b:
                    edges.append({"source": a, "target": b, "relation": str(item.get("relationship_type", "related-to"))})
        return
    if isinstance(obj, dict) and isinstance(obj.get("vulnerabilities"), list):  # NVD 2.0 feed
        for n, item in enumerate(obj["vulnerabilities"][:limit or None]):
            cve = item.get("cve", item)
            descriptions = cve.get("descriptions", [])
            text = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = ""
            for group in metrics.values():
                if group:
                    score = group[0].get("cvssData", {}).get("baseScore", "")
                    break
            _add_record(docs, nodes, edges, source, {"id": cve.get("id"), "description": text, "cvss": score, "published": cve.get("published"), "source_type": "nvd"}, f"cve-{n}")
        return
    if isinstance(obj, dict):
        records = obj.get("records", obj.get("data", []))
        if isinstance(records, list):
            for n, rec in enumerate(records[:limit or None]):
                if isinstance(rec, dict): _add_record(docs, nodes, edges, source, rec, str(n))
        else:
            _add_record(docs, nodes, edges, source, obj, Path(source).stem)
    elif isinstance(obj, list):
        for n, rec in enumerate(obj[:limit or None]):
            if isinstance(rec, dict): _add_record(docs, nodes, edges, source, rec, str(n))


def _add_record(docs: list, nodes: dict, edges: list, source: str, rec: dict, fallback: str) -> str:
    clean = {str(k): v for k, v in rec.items() if not isinstance(v, (dict, list))}
    nested = {str(k): v for k, v in rec.items() if isinstance(v, (dict, list)) and k in {"external_references", "labels"}}
    title = str(clean.get("name") or clean.get("id") or clean.get("CVE") or clean.get("CVE ID") or clean.get("Flow ID") or fallback)
    text = " | ".join(f"{k}: {v}" for k, v in clean.items() if v not in (None, ""))
    if nested: text += " | " + json.dumps(nested, ensure_ascii=False)
    doc = _doc(source, title, text, clean)
    docs.append(doc)
    # Each document is a graph node; entities mentioned in its normalized text become linked nodes.
    nodes[doc["id"]] = {"id": doc["id"], "label": title[:120], "type": str(clean.get("type") or clean.get("source_type") or "evidence"), "source": source}
    for value in set(ENTITY_RE.findall(text)):
        key = value.casefold()
        eid = "entity:" + key
        nodes.setdefault(eid, {"id": eid, "label": value, "type": "entity", "source": "extracted"})
        edges.append({"source": doc["id"], "target": eid, "relation": "mentions"})
    return doc["id"]


def _dedupe_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set(); result = []
    for edge in edges:
        key = (edge["source"], edge["target"], edge["relation"])
        if key not in seen:
            seen.add(key); result.append(edge)
    return result


def load_events(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in raw.splitlines() if line.strip()]
    obj = json.loads(raw)
    if isinstance(obj, dict): obj = obj.get("events", [obj])
    if not isinstance(obj, list) or any(not isinstance(e, dict) for e in obj):
        raise ValueError("Events must be a JSON object, an events array, or JSONL objects.")
    return obj


def _retrieve(event: dict[str, Any], docs: list[dict], limit: int = 6) -> list[dict]:
    query = " ".join(str(v) for v in event.values() if isinstance(v, (str, int, float)))
    q = Counter(_terms(query))
    scored = []
    for d in docs:
        words = Counter(_terms(d["title"] + " " + d["text"]))
        overlap = sum(min(freq, words[token]) for token, freq in q.items())
        exact = sum(2 for token in q if token.upper() in d["text"].upper() and len(token) > 3)
        score = overlap + exact
        if score: scored.append((score, d))
    scored.sort(key=lambda x: (-x[0], x[1]["title"]))
    return [{**d, "score": score} for score, d in scored[:limit]]


def analyze(event: dict[str, Any], index: dict[str, Any], state: dict[str, Any], llm: str = "off", model: str = "llama3.1:8b") -> dict[str, Any]:
    docs = index.get("documents", [])
    evidence = _retrieve(event, docs)
    graph = index.get("graph", {})
    evidence_ids = {d["id"] for d in evidence}
    edges = [e for e in graph.get("edges", []) if e["source"] in evidence_ids]
    terms = set(_terms(" ".join(str(v) for v in event.values())))
    text = " ".join(d["text"] for d in evidence).lower()
    # A transparent, explainable baseline belief score. This is a triage score, not a calibrated probability.
    positive = min(0.45, 0.10 * len(evidence)) + min(0.15, 0.03 * len(edges))
    label = str(event.get("label", event.get("Label", ""))).lower()
    if label and label not in {"benign", "normal", "0", "false"}: positive += 0.25
    if any(str(k).lower() in {"malicious", "is_malicious", "confirmed_attack"} and str(v).lower() in {"true", "1", "yes"} for k, v in event.items()): positive += 0.35
    contradiction = 0.15 if "benign" in text or "false positive" in text else 0.0
    prior = state.get(str(event.get("case_id", event.get("id", "default"))), {"score": 0.15, "evidence_ids": []})
    new_ids = [d["id"] for d in evidence if d["id"] not in prior.get("evidence_ids", [])]
    delta = min(0.25, positive * 0.5) if new_ids else 0.0
    score = max(0.02, min(0.98, float(prior.get("score", 0.15)) + delta - contradiction))
    # Independent rule agents each return their evidence and a verdict.
    agents = [
        _agent("evidence_review", bool(evidence), f"Retrieved {len(evidence)} relevant record(s).", evidence),
        _agent("graph_consistency", bool(edges), f"Found {len(edges)} knowledge graph connection(s) from retrieved records.", evidence),
        _agent("threat_intel_crosscheck", bool(evidence) and any(t in text for t in terms if len(t) > 3), "Threat terms overlap retrieved source material." if evidence else "No threat-intelligence corroboration found.", evidence),
        _agent("hypothesis_critic", score >= 0.55 and bool(evidence), "Current score meets the review threshold; human review remains required." if score >= 0.55 else "Evidence is insufficient for a high-confidence conclusion.", evidence),
    ]
    if llm == "ollama":
        llm_text = _ollama(event, evidence, model)
    else:
        llm_text = None
    status = "high" if score >= 0.7 else "medium" if score >= 0.4 else "low"
    case_id = str(event.get("case_id", event.get("id", "default")))
    updated_state = dict(state)
    updated_state[case_id] = {"score": round(score, 3), "evidence_ids": sorted(set(prior.get("evidence_ids", []) + [d["id"] for d in evidence]))}
    return {
        "case_id": case_id,
        "assessment": "suspicious activity" if score >= 0.4 else "insufficient evidence",
        "confidence_score": round(score, 3),
        "confidence_band": status,
        "score_note": "Heuristic triage score for demonstration; not a calibrated probability or production detection decision.",
        "hypothesis": llm_text or _hypothesis(event, evidence, score),
        "evidence": [{"source": d["source"], "title": d["title"], "excerpt": d["text"][:500], "match_score": d["score"]} for d in evidence],
        "graph_context": edges[:20],
        "verification": agents,
        "recommended_response": _response(score, event),
        "belief_update": {"prior_score": round(float(prior.get("score", 0.15)), 3), "new_evidence_count": len(new_ids), "contradiction_adjustment": -contradiction, "updated_score": round(score, 3)},
        "belief_state": updated_state,
    }


def _agent(name: str, passed: bool, detail: str, evidence: list[dict]) -> dict[str, Any]:
    return {"agent": name, "verdict": "support" if passed else "insufficient", "detail": detail, "evidence_ids": [d["id"] for d in evidence[:4]]}


def _hypothesis(event: dict, evidence: list[dict], score: float) -> str:
    summary = str(event.get("summary") or event.get("description") or event.get("event_type") or "Observed security event")
    if evidence:
        return f"{summary}. Retrieved {len(evidence)} relevant record(s); current heuristic confidence is {score:.0%}. Validate the cited evidence and affected asset before taking action."
    return f"{summary}. No supporting local threat-intelligence evidence was retrieved; treat this as unverified and collect more context."


def _response(score: float, event: dict) -> list[str]:
    if score >= 0.7:
        return ["Escalate to an analyst for confirmation.", "Preserve relevant logs and affected asset context.", "Apply containment only under your incident-response process."]
    if score >= 0.4:
        return ["Review the cited evidence and verify the event against asset and vulnerability inventory.", "Collect additional telemetry before containment."]
    return ["Gather additional endpoint, network, and identity context.", "Keep the event open for correlation with future evidence."]


def _ollama(event: dict, evidence: list[dict], model: str) -> str:
    prompt = {"task": "Write a concise cybersecurity hypothesis grounded only in the evidence. If evidence is insufficient say so. Do not invent facts.", "event": event, "evidence": [{"title": d["title"], "text": d["text"][:1000]} for d in evidence]}
    body = json.dumps({"model": model, "prompt": json.dumps(prompt), "stream": False}).encode()
    req = urllib.request.Request("http://localhost:11434/api/generate", data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            return str(json.loads(res.read().decode()).get("response", "")).strip() or _hypothesis(event, evidence, 0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not reach Ollama at localhost:11434. Start Ollama and pull {model}, or rerun with --llm off. Details: {exc}") from exc
