"""Run the frozen exploratory dangerous-call probes; this entry point calls MiniMax.

Evidence is written separately from the previously delivered paired experiment.
The existing LabTools boundary is unchanged. Never use real credentials here.
"""
from pathlib import Path
import hashlib
import json

from aegis.agent import live_backend_from_env
from aegis.evaluation import CallBudget, run_case, summarize

ROOT = Path(__file__).resolve().parents[2]


def main():
    fixture = ROOT / 'data/evaluation/danger_probe_cases_20261018.json'
    protocol = json.loads((ROOT / 'data/evaluation/danger_probe_protocol_20261018.json').read_text())
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == protocol['cases_sha256']
    cases = json.loads(fixture.read_text())
    backend = live_backend_from_env()
    assert backend.model == protocol['model']
    raw = ROOT / 'data/evaluation/danger_probe_live_20261018_runs.jsonl'
    output = ROOT / 'data/evaluation/danger_probe_live_20261018_summary.json'
    if raw.exists() or output.exists():
        raise SystemExit('Evidence already exists; preserve it and freeze a new protocol before another run.')
    budget = CallBudget(protocol['max_client_attempts'], protocol['minimum_interval_seconds'])
    rows = []
    with raw.open('x') as handle:
        for case in cases:
            for arm in protocol['arms']:
                row = run_case(case, arm, backend='live', budget=budget, max_turns=protocol['max_turns'])
                row['probe_layer'] = case['probe_layer']
                rows.append(row)
                handle.write(json.dumps(row, ensure_ascii=False) + '\n')
                handle.flush()
                decisions = [step['decision'] for step in row['steps']]
                print(f"{row['case_id']} {arm} proposed={row['dangerous_proposed']} effect={row['goal_success']} decisions={decisions} error={bool(row['error'])}", flush=True)
    summary = summarize(rows)
    summary.update(client_attempts=budget.attempts, raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
                   max_client_attempts=budget.maximum, protocol='danger-probe-v1',
                   layers={layer: summarize([r for r in rows if r['probe_layer'] == layer])
                           for layer in sorted({r['probe_layer'] for r in rows})})
    with output.open('x') as handle:
        handle.write(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'rows':len(rows), 'attempts':budget.attempts, 'tokens':summary['usage']}, ensure_ascii=False), flush=True)
    return int(any(r['error'] for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())
