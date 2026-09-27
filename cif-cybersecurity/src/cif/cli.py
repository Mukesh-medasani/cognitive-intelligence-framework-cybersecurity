from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import analyze, build_index, load_events


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cif", description="CIF cybersecurity analysis prototype")
    sub = p.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the included end-to-end example")
    demo.add_argument("--data", type=Path, default=Path("data/sample"), help="sample data folder")
    demo.add_argument("--output", type=Path, default=Path("reports/demo.json"))
    demo.add_argument("--llm", choices=("off", "ollama"), default="off")
    demo.add_argument("--model", default="llama3.1:8b")

    index = sub.add_parser("index", help="read local CTI, ATT&CK, CVE, KEV, and flow files")
    index.add_argument("--data", type=Path, default=Path("data/raw"))
    index.add_argument("--output", type=Path, default=Path("reports/index.json"))
    index.add_argument("--max-csv-rows", type=int, default=2000,
                       help="maximum rows indexed per CSV (use 0 for all rows)")

    run = sub.add_parser("analyze", help="analyze events using a built index")
    run.add_argument("--index", type=Path, default=Path("reports/index.json"))
    run.add_argument("--events", type=Path, required=True, help="JSON or JSONL event file")
    run.add_argument("--output", type=Path, default=Path("reports/analysis.json"))
    run.add_argument("--state", type=Path, default=Path("reports/beliefs.json"))
    run.add_argument("--llm", choices=("off", "ollama"), default="off")
    run.add_argument("--model", default="llama3.1:8b")
    return p


def main() -> None:
    args = parser().parse_args()
    try:
        if args.command == "demo":
            index_data = build_index(args.data, max_csv_rows=0)
            events = load_events(args.data / "security_events.jsonl")
            results = [analyze(e, index_data, {}, args.llm, args.model) for e in events]
            _write(args.output, {"mode": "demo", "results": results})
            print(f"Analyzed {len(results)} sample event(s). Report: {args.output.resolve()}")
        elif args.command == "index":
            data = build_index(args.data, args.max_csv_rows)
            _write(args.output, data)
            print(f"Indexed {len(data['documents'])} documents and {len(data['graph']['nodes'])} graph nodes.")
            print(f"Index: {args.output.resolve()}")
        elif args.command == "analyze":
            index_data = json.loads(args.index.read_text(encoding="utf-8"))
            events = load_events(args.events)
            state = json.loads(args.state.read_text(encoding="utf-8")) if args.state.exists() else {}
            results = []
            for event in events:
                result = analyze(event, index_data, state, args.llm, args.model)
                state = result["belief_state"]
                results.append(result)
            _write(args.state, state)
            _write(args.output, {"mode": "analysis", "results": results})
            print(f"Analyzed {len(results)} event(s). Report: {args.output.resolve()}")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"CIF could not complete the request: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _write(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
