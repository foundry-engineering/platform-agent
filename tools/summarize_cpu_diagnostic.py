"""Publish numeric pinned-engine timings, never raw engine logs or prompts."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def summarize(raw: str) -> dict[str, Any]:
    progress = [
        {'tokens': int(match[1]), 'progress': float(match[2]),
         'seconds': float(match[3]), 'tokensPerSecond': float(match[4])}
        for match in re.finditer(
            r'prompt processing, n_tokens =\s*(\d+), progress = ([0-9.]+), '
            r't =\s*([0-9.]+) s / ([0-9.]+) tokens per second', raw)
    ][-32:]
    timings = [
        {'phase': 'prompt' if match[1] else 'generation', 'milliseconds': float(match[2]),
         'tokens': int(match[3]), 'millisecondsPerToken': float(match[4]),
         'tokensPerSecond': float(match[5])}
        for match in re.finditer(
            r'(prompt )?\s*eval time =\s*([0-9.]+) ms /\s*(\d+) tokens '
            r'\(\s*([0-9.]+) ms per token,\s*([0-9.]+) tokens per second\)', raw)
    ][-16:]
    generated = [
        {'tokens': int(match[1]), 'tokensPerSecond': float(match[2]),
         'recentTokensPerSecond': float(match[3])}
        for match in re.finditer(
            r'n_gen =\s*(\d+), tg =\s*([0-9.]+) t/s, tg_3s =\s*([0-9.]+) t/s', raw)
    ][-16:]
    return {'schemaVersion': 'foundry.public-fixture-cpu-diagnostics.v1',
        'testHarnessInstrumentedForPrivateStderr': True,
        'engineArgumentsAndWeightsUnchanged': True, 'promptProgress': progress,
        'completedTimings': timings, 'generationProgress': generated,
        'enterpriseReleaseApproved': False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = ''
    if args.log.exists():
        with args.log.open('rb') as stream:
            stream.seek(max(0, args.log.stat().st_size - 512_000))
            raw = stream.read(512_001).decode('utf-8', errors='replace')
    report = summarize(raw)
    with args.output.open('x') as stream:
        args.output.chmod(0o600)
        json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
    print('CPU_DIAGNOSTICS=' + json.dumps(report, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
