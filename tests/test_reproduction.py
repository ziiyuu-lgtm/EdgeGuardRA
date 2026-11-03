import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from edgeguardra import __version__
from edgeguardra.__main__ import main
from edgeguardra.environment import check_environment, collect_environment
from edgeguardra.reproduce import run_reproduction, summarize_runs
from edgeguardra.worked_example import run_worked_example


class ReproductionTests(unittest.TestCase):
    def test_worked_evidence_review_and_single_use(self):
        result = run_worked_example()
        steps = {s['stage']: s for s in result['steps']}
        self.assertEqual(steps['unknown_context']['outcome'], 'defer')
        self.assertEqual(steps['signed_evidence']['code'], 'evidence_accepted')
        self.assertEqual(steps['critical_proposal']['code'], 'review_required')
        self.assertEqual(steps['review']['code'], 'approved_for_sandbox')
        self.assertTrue(steps['execute_once']['executed'])
        self.assertFalse(steps['execute_again']['executed'])
        self.assertEqual(steps['evidence_replay']['code'], 'evidence_replay')
        self.assertEqual(steps['tampered_proposal']['code'], 'invalid_signature')
        self.assertEqual(result['final_device']['quarantined'], 1)
        self.assertTrue(result['audit']['valid'])
        self.assertFalse(result['audit']['anchored'])

    def test_worked_example_cli_is_json(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(main(['worked-example']), 0)
        self.assertEqual(json.loads(stream.getvalue())['version'], __version__)

    def test_bootstrap_uses_runs_and_reports_variation(self):
        result = summarize_runs([20., 40.], resamples=1000)
        self.assertEqual(result['mean'], 30.)
        self.assertAlmostEqual(result['sample_sd'], 2 ** .5 * 10)
        self.assertEqual(result['bootstrap_mean_ci95'], [20., 40.])
        self.assertEqual(result, summarize_runs([20., 40.], resamples=1000))

    def test_invalid_measurements_are_not_silently_omitted(self):
        for values in ([], [1.], [1., float('nan')], [1., float('inf')], [1., -1.], [True, 1.]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                summarize_runs(values)

    def test_environment_lock_reports_mismatch(self):
        env = collect_environment()
        required = {k: env[k] for k in ('python', 'implementation', 'sqlite')}
        required['packages'] = {k: v for k, v in env['packages'].items() if v is not None}
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'lock.json'
            p.write_text(json.dumps({'required': required}))
            self.assertTrue(check_environment(p)['matches'])
            required['sqlite'] = '0.0.0'
            p.write_text(json.dumps({'required': required}))
            self.assertEqual(check_environment(p)['mismatches'][0]['component'], 'sqlite')
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['check-environment', str(p)]), 1)

    def test_invalid_environment_lock_fails_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'lock.json'
            for raw in ('null', '[]', '{}', '{"required": null}', 'broken', 'x' * 65537):
                p.write_text(raw)
                err = io.StringIO()
                with self.subTest(raw=raw[:20]), redirect_stderr(err):
                    self.assertEqual(main(['check-environment', str(p)]), 2)
                    self.assertNotIn('Traceback', err.getvalue())

    def test_invalid_reproduction_options_create_no_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'new'
            for kwargs in ({'repeats': 1}, {'repeats': True}, {'repeats': 31},
                           {'latency_samples': 1}, {'figures': 1}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    run_reproduction(out, **kwargs)
                self.assertFalse(out.exists())

    def test_existing_output_is_not_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'old'
            out.mkdir()
            (out / 'keep').write_text('original')
            with self.assertRaises(FileExistsError):
                run_reproduction(out, repeats=2, latency_samples=10)
            self.assertEqual((out / 'keep').read_text(), 'original')

    def test_failed_child_does_not_claim_complete_or_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'new'
            with patch('edgeguardra.reproduce.subprocess.run',
                       return_value=subprocess.CompletedProcess([], 2)) as child:
                with self.assertRaisesRegex(ValueError, 'incomplete output retained'):
                    run_reproduction(out, repeats=2, latency_samples=10)
            self.assertEqual(child.call_count, 1)
            self.assertTrue((out / 'environment.json').exists())
            self.assertFalse((out / 'manifest.json').exists())

    def test_fresh_process_reproduction_retains_raw_data_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'new'
            result = run_reproduction(out, repeats=2, latency_samples=10)
            self.assertEqual(result['latency_samples_total'], 20)
            self.assertEqual(result['checkpoint_samples_total'], 240)
            self.assertTrue(result['functional_results_identical'])
            self.assertEqual(result['results']['risk']['matches_desired'], 48)
            for index in (1, 2):
                run = out / f'run-{index:02d}'
                self.assertTrue((run / 'timing_samples.csv').exists())
                self.assertTrue((run / 'checkpoint_timing_samples.csv').exists())
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertTrue(manifest['complete'])
            for relative, digest in manifest['sha256'].items():
                self.assertEqual(hashlib.sha256((out / relative).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
