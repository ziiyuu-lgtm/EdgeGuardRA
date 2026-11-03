"""The CLI should reject malformed bounded inputs without an uncaught traceback."""
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class CliInputBoundaryTests(unittest.TestCase):
    def test_deeply_nested_policy_is_cleanly_rejected(self):
        with TemporaryDirectory() as tmp:
            policy = Path(tmp) / 'nested.json'
            policy.write_text('[' * 12000 + ']' * 12000, encoding='ascii')
            result = subprocess.run([sys.executable, '-m', 'edgeguardra', 'check-policy', str(policy)],
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn('EdgeGuardRA error:', result.stderr)
        self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
