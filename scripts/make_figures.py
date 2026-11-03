"""Regenerate figures without changing the bundled snapshot."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from edgeguardra.figures import make_figures

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--snapshot', default='results/reproduction/run-01/summary.json')
p.add_argument('--out', required=True, help='new figure directory')
a = p.parse_args()
try:
    print('\n'.join(make_figures(a.snapshot, a.out)))
except (ValueError, OSError, ImportError) as exc:
    p.exit(2, 'EdgeGuardRA figure error: ' + str(exc) + '\n')
