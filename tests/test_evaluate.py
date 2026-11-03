import tempfile
import unittest
from pathlib import Path
from edgeguardra.evaluate import KINDS, REVIEW_EXPECTED, run, run_cases, run_review_cases, summary_for


class EvaluationTests(unittest.TestCase):
    def test_scenario_labels_and_known_residual(self):
        rows=run_cases(1);s=summary_for(rows)
        self.assertEqual(len(rows),4*len(KINDS))
        self.assertEqual(s['risk']['by_kind']['false_positive_evidence'],{'allow':1})
        false_row=next(r for r in rows if r['kind']=='false_positive_evidence' and r['mode']=='risk')
        self.assertEqual(false_row['evidence_method'],'signed_source')
        self.assertEqual((false_row['ground_truth'],false_row['signal']),('normal','compromised'))
        self.assertEqual(s['risk']['by_kind']['critical_review'],{'defer':1})
        self.assertEqual(s['risk']['by_kind']['replay'],{'block':1})

    def test_run_does_not_overwrite_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'snapshot';out.mkdir();(out/'summary.json').write_text('keep')
            with self.assertRaises(FileExistsError): run(out,variants=1,latency_samples=10)
            self.assertEqual((out/'summary.json').read_text(),'keep')

    def test_new_run_produces_raw_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'new';s=run(out,variants=1,latency_samples=10)
            self.assertTrue((out/'timing_samples.csv').exists())
            self.assertTrue((out/'review_decisions.csv').exists())
            self.assertTrue((out/'checkpoint_timing_samples.csv').exists())
            self.assertEqual(s['checkpoint_read_latency']['samples_per_mode_and_size'],20)
            self.assertEqual(set(s['checkpoint_read_latency']['by_size']),{'10','100','500'})
            self.assertEqual(s['cases_per_mode'],len(KINDS))
            self.assertEqual(s['review_evaluation']['cases'],len(REVIEW_EXPECTED))

    def test_review_study_records_expected_branches(self):
        rows=run_review_cases(1)
        self.assertEqual(len(rows),len(REVIEW_EXPECTED))
        self.assertTrue(all(row['matches_expected'] for row in rows))
        self.assertTrue(next(row for row in rows if row['kind']=='valid_review')['simulated_execution'])
        self.assertEqual(next(row for row in rows if row['kind']=='replayed_approval')['first_approval_code'],'approved_for_sandbox')

    def test_invalid_parameters_do_not_create_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'new'
            with self.assertRaises(ValueError):run(out,variants=0)
            self.assertFalse(out.exists())
            with self.assertRaises(ValueError):run(out,latency_samples=1)
            self.assertFalse(out.exists())


if __name__=='__main__': unittest.main()

